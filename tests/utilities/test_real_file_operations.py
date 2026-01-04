"""
Tests for real file operations in Intellicrack.

This module contains comprehensive tests for real file handling operations
including binary file I/O, file resolution, path discovery, binary utilities,
file monitoring, secure file operations, compression, and metadata handling.
The tests validate that the file operations work correctly for security
research and binary analysis tasks.
"""

import pytest
import tempfile
import os
import struct
import shutil
import time
from pathlib import Path
import hashlib

from typing import Any, Generator
from intellicrack.utils.system.file_resolution import FileResolver
from intellicrack.utils.binary.binary_io import BinaryIO  # type: ignore[attr-defined]
from intellicrack.utils.binary.binary_utils import BinaryUtils  # type: ignore[attr-defined]
from intellicrack.utils.core.path_discovery import PathDiscovery
from intellicrack.utils.system.system_utils import SystemUtils  # type: ignore[attr-defined]
from intellicrack.core.app_context import AppContext


class TestRealFileOperations:
    """Functional tests for REAL file handling operations."""

    @pytest.fixture
    def test_binary_content(self) -> bytes:
        """Create REAL binary content for testing."""
        # PE header
        pe_data = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        pe_data += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
        pe_data += b'\x00' * 32
        pe_data += b'\x80\x00\x00\x00'  # PE offset
        pe_data += b'\x00' * 60
        pe_data += b'PE\x00\x00'  # PE signature
        pe_data += b'\x4c\x01\x03\x00' + b'\x00' * 16  # COFF header

        # Add sections
        pe_data += b'.text\x00\x00\x00'
        pe_data += struct.pack('<I', 0x1000)  # Virtual size
        pe_data += struct.pack('<I', 0x1000)  # Virtual address
        pe_data += b'\x00' * 24

        # Add code
        pe_data += b'\x55\x8b\xec'  # push ebp; mov ebp, esp
        pe_data += b'\x83\xec\x10'  # sub esp, 16
        pe_data += b'\xe8\x00\x00\x00\x00'  # call
        pe_data += b'\x8b\xe5\x5d\xc3'  # mov esp, ebp; pop ebp; ret

        # Pad to realistic size
        pe_data += b'\x90' * (4096 - len(pe_data))

        return pe_data

    @pytest.fixture
    def test_directory(self) -> Generator[str, None, None]:
        """Create REAL test directory structure."""
        temp_dir = tempfile.mkdtemp(prefix='intellicrack_test_')

        # Create subdirectories
        subdirs = ['binaries', 'output', 'cache', 'plugins']
        for subdir in subdirs:
            os.makedirs(os.path.join(temp_dir, subdir), exist_ok=True)

        yield temp_dir

        # Cleanup
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    @pytest.fixture
    def app_context(self) -> AppContext:
        """Create REAL application context."""
        context = AppContext()
        context.initialize()  # type: ignore[attr-defined]
        return context

    def test_real_binary_file_io_operations(self, test_binary_content: bytes, test_directory: str, app_context: AppContext) -> None:
        """Test REAL binary file I/O operations."""
        binary_io = BinaryIO()

        test_file = os.path.join(test_directory, 'binaries', 'test.exe')

        # Write binary file
        write_result = binary_io.write_binary_file(test_file, test_binary_content)
        assert write_result is not None, "Binary write must succeed"
        assert write_result['success'], "Write operation must be successful"
        assert write_result['bytes_written'] == len(test_binary_content), "All bytes must be written"

        # Verify file exists
        assert os.path.exists(test_file), "File must exist after write"
        assert os.path.getsize(test_file) == len(test_binary_content), "File size must match"

        # Read binary file
        read_result = binary_io.read_binary_file(test_file)
        assert read_result is not None, "Binary read must succeed"
        assert 'data' in read_result, "Read result must contain data"
        assert read_result['data'] == test_binary_content, "Read data must match written data"
        assert read_result['size'] == len(test_binary_content), "Size must match"

        # Read with offset and size
        partial_result = binary_io.read_binary_file(test_file, offset=128, size=256)
        assert partial_result is not None, "Partial read must succeed"
        assert len(partial_result['data']) == 256, "Partial read size must match"
        assert partial_result['data'] == test_binary_content[128:384], "Partial data must match"

        # Test memory mapping
        mmap_result = binary_io.memory_map_file(test_file)
        assert mmap_result is not None, "Memory mapping must succeed"
        assert 'mmap' in mmap_result, "Result must contain mmap object"
        assert 'size' in mmap_result, "Result must contain size"

        # Read from memory map
        mmap_data = mmap_result['mmap'][:4]
        assert mmap_data == b'MZ\x90\x00', "Memory mapped data must match"

        # Close memory map
        binary_io.close_memory_map(mmap_result['mmap'])

    def test_real_file_resolution_operations(self, test_directory: str, app_context: AppContext) -> None:
        """Test REAL file resolution and path discovery."""
        resolver = FileResolver()
        path_discovery = PathDiscovery()

        # Create test files with different extensions
        test_files = {
            'program.exe': b'MZ' + b'\x00' * 100,
            'library.dll': b'MZ' + b'\x00' * 100,
            'script.py': b'#!/usr/bin/env python\n',
            'config.ini': b'[settings]\nkey=value\n',
            'data.bin': os.urandom(256)
        }

        for filename, content in test_files.items():
            filepath = os.path.join(test_directory, filename)
            with open(filepath, 'wb') as f:
                f.write(content)

        # Test file resolution
        exe_path = resolver.resolve_file('program.exe', search_paths=[test_directory])  # type: ignore[attr-defined]
        assert exe_path is not None, "EXE file must be resolved"
        assert os.path.exists(exe_path), "Resolved path must exist"
        assert exe_path.endswith('program.exe'), "Must resolve correct file"

        # Test wildcard resolution
        dll_files = resolver.resolve_files_wildcard('*.dll', test_directory)  # type: ignore[attr-defined]
        assert dll_files is not None, "Wildcard resolution must succeed"
        assert len(dll_files) == 1, "Must find one DLL file"
        assert dll_files[0].endswith('library.dll'), "Must find correct DLL"

        # Test extension filtering
        binary_files = resolver.find_files_by_extension(test_directory, ['.exe', '.dll'])  # type: ignore[attr-defined]
        assert len(binary_files) == 2, "Must find two binary files"

        # Test path discovery
        system_paths = path_discovery.get_system_paths()  # type: ignore[attr-defined]
        assert system_paths is not None, "System paths must be discovered"
        assert 'system32' in system_paths or 'System32' in str(system_paths), \
            "Must include system directories"

        # Test program discovery
        program_paths = path_discovery.discover_program_paths(['notepad.exe', 'cmd.exe'])  # type: ignore[attr-defined]
        assert program_paths is not None, "Program discovery must succeed"
        if len(program_paths) > 0:
            for prog, path in program_paths.items():
                if path:
                    assert os.path.exists(path), f"Discovered path for {prog} must exist"

    def test_real_binary_utils_operations(self, test_binary_content: bytes, test_directory: str, app_context: AppContext) -> None:
        """Test REAL binary utility operations."""
        binary_utils = BinaryUtils()

        # Create test binary
        test_file = os.path.join(test_directory, 'test_binary.exe')
        with open(test_file, 'wb') as f:
            f.write(test_binary_content)

        # Calculate hashes
        hash_result = binary_utils.calculate_file_hashes(test_file)
        assert hash_result is not None, "Hash calculation must succeed"
        assert 'md5' in hash_result, "Must calculate MD5"
        assert 'sha1' in hash_result, "Must calculate SHA1"
        assert 'sha256' in hash_result, "Must calculate SHA256"

        # Verify hash format
        assert len(hash_result['md5']) == 32, "MD5 must be 32 hex chars"
        assert len(hash_result['sha1']) == 40, "SHA1 must be 40 hex chars"
        assert len(hash_result['sha256']) == 64, "SHA256 must be 64 hex chars"

        # Extract strings
        strings_result = binary_utils.extract_strings(test_file, min_length=4)
        assert strings_result is not None, "String extraction must succeed"
        assert 'ascii_strings' in strings_result, "Must extract ASCII strings"
        assert 'unicode_strings' in strings_result, "Must extract Unicode strings"

        # Find patterns
        pattern_result = binary_utils.find_binary_patterns(
            test_file,
            patterns={
                'pe_header': b'MZ',
                'pe_signature': b'PE\x00\x00',
                'code_start': b'\x55\x8b\xec'
            }
        )
        assert pattern_result is not None, "Pattern search must succeed"
        assert 'pe_header' in pattern_result, "Must find PE header"
        assert pattern_result['pe_header'][0] == 0, "PE header must be at offset 0"

        # Binary diff
        modified_content = test_binary_content[:100] + b'\xff\xff\xff\xff' + test_binary_content[104:]
        modified_file = os.path.join(test_directory, 'modified.exe')
        with open(modified_file, 'wb') as f:
            f.write(modified_content)

        diff_result = binary_utils.binary_diff(test_file, modified_file)
        assert diff_result is not None, "Binary diff must succeed"
        assert 'differences' in diff_result, "Must contain differences"
        assert len(diff_result['differences']) > 0, "Must detect differences"

        # Check difference details
        first_diff = diff_result['differences'][0]
        assert first_diff['offset'] == 100, "Difference must be at correct offset"
        assert first_diff['size'] == 4, "Difference size must be correct"

    def test_real_file_chunking_operations(self, test_directory: str, app_context: AppContext) -> None:
        """Test REAL file chunking for large files."""
        binary_io = BinaryIO()

        # Create large test file (10MB)
        large_file = os.path.join(test_directory, 'large_file.bin')
        chunk_size = 1024 * 1024  # 1MB chunks
        total_size = 10 * chunk_size

        # Write large file in chunks
        with open(large_file, 'wb') as f:
            for i in range(10):
                chunk_data = os.urandom(chunk_size)
                f.write(chunk_data)

        assert os.path.getsize(large_file) == total_size, "Large file must be correct size"

        # Read file in chunks
        chunks_read = []
        chunk_result = binary_io.read_file_chunks(large_file, chunk_size=chunk_size)
        assert chunk_result is not None, "Chunk reading must succeed"

        for chunk_info in chunk_result['chunks']:
            assert 'offset' in chunk_info, "Chunk must have offset"
            assert 'size' in chunk_info, "Chunk must have size"
            assert 'data' in chunk_info, "Chunk must have data"
            chunks_read.append(chunk_info)

        assert len(chunks_read) == 10, "Must read correct number of chunks"

        # Verify chunk continuity
        for i, chunk in enumerate(chunks_read):
            assert chunk['offset'] == i * chunk_size, f"Chunk {i} offset must be correct"
            assert chunk['size'] == chunk_size, f"Chunk {i} size must be correct"

        # Process file with callback
        processed_chunks = []

        def process_chunk(chunk_data: bytes, offset: int, size: int) -> bool:
            processed_chunks.append({
                'offset': offset,
                'size': size,
                'hash': hashlib.md5(chunk_data).hexdigest()
            })
            return True

        process_result = binary_io.process_file_chunks(
            large_file,
            process_chunk,
            chunk_size=chunk_size
        )

        assert process_result is not None, "Chunk processing must succeed"
        assert process_result['chunks_processed'] == 10, "All chunks must be processed"
        assert len(processed_chunks) == 10, "Callback must process all chunks"

    def test_real_file_monitoring_operations(self, test_directory: str, app_context: AppContext) -> None:
        """Test REAL file monitoring and change detection."""
        system_utils = SystemUtils()

        monitor_file = os.path.join(test_directory, 'monitored.txt')
        with open(monitor_file, 'w') as f:
            f.write("Initial content")

        # Get initial file info
        initial_info = system_utils.get_file_info(monitor_file)
        assert initial_info is not None, "File info must be retrieved"
        assert 'size' in initial_info, "Must have size"
        assert 'modified_time' in initial_info, "Must have modified time"
        assert 'created_time' in initial_info, "Must have created time"

        initial_size = initial_info['size']
        initial_mtime = initial_info['modified_time']

        # Wait and modify file
        time.sleep(0.1)
        with open(monitor_file, 'a') as f:
            f.write("\nModified content")

        # Check for changes
        new_info = system_utils.get_file_info(monitor_file)
        assert new_info['size'] > initial_size, "File size must increase"
        assert new_info['modified_time'] > initial_mtime, "Modified time must update"

        # Monitor multiple files
        monitor_files = []
        for i in range(5):
            filepath = os.path.join(test_directory, f'monitor_{i}.txt')
            with open(filepath, 'w') as f:
                f.write(f"File {i}")
            monitor_files.append(filepath)

        # Create file watcher
        watcher_result = system_utils.create_file_watcher(
            test_directory,
            patterns=['*.txt'],
            recursive=False
        )

        assert watcher_result is not None, "File watcher creation must succeed"
        assert 'watcher_id' in watcher_result, "Must have watcher ID"

        # Simulate file changes
        changes_detected: list[Any] = []
        with open(monitor_files[0], 'a') as f:
            f.write(" - modified")

        os.remove(monitor_files[1])

        with open(os.path.join(test_directory, 'new_file.txt'), 'w') as f:
            f.write("New file content")

        # Check for detected changes (with small delay for filesystem)
        time.sleep(0.1)
        if changes := system_utils.get_file_changes(watcher_result['watcher_id']):
            assert 'modified' in changes or 'created' in changes or 'deleted' in changes, \
                    "Must detect file changes"

    def test_real_secure_file_operations(self, test_directory: str, app_context: AppContext) -> None:
        """Test REAL secure file operations."""
        binary_io = BinaryIO()
        system_utils = SystemUtils()

        sensitive_file = os.path.join(test_directory, 'sensitive.dat')
        sensitive_data = b'CONFIDENTIAL_DATA_' + os.urandom(32)

        # Write with secure permissions
        secure_write = binary_io.write_secure_file(
            sensitive_file,
            sensitive_data,
            permissions=0o600  # Owner read/write only
        )

        assert secure_write is not None, "Secure write must succeed"
        assert secure_write['success'], "Secure write must be successful"

        # Verify permissions (platform-specific)
        if hasattr(os, 'stat'):
            stat_info = os.stat(sensitive_file)
            mode = stat_info.st_mode & 0o777
            # On Windows, permissions might be different
            assert mode <= 0o700, "File permissions must be restrictive"

        # Secure delete with overwrite
        shred_result = system_utils.secure_delete_file(
            sensitive_file,
            passes=3,
            random_data=True
        )

        assert shred_result is not None, "Secure delete must succeed"
        assert shred_result['success'], "Secure delete must be successful"
        assert not os.path.exists(sensitive_file), "File must be deleted"

        # Test locked file handling
        locked_file = os.path.join(test_directory, 'locked.txt')
        with open(locked_file, 'w') as f:
            f.write("Locked content")

        # Try to handle locked file scenarios
        lock_test = system_utils.test_file_lock(locked_file)
        assert lock_test is not None, "Lock test must return result"
        assert 'can_read' in lock_test, "Must test read access"
        assert 'can_write' in lock_test, "Must test write access"

    def test_real_file_compression_operations(self, test_directory: str, test_binary_content: bytes, app_context: AppContext) -> None:
        """Test REAL file compression and archiving."""
        binary_utils = BinaryUtils()

        # Create test files
        files_to_compress = []
        for i in range(5):
            filepath = os.path.join(test_directory, f'file_{i}.bin')
            with open(filepath, 'wb') as f:
                f.write(test_binary_content + os.urandom(100))
            files_to_compress.append(filepath)

        # Compress files
        archive_path = os.path.join(test_directory, 'compressed.zip')
        compress_result = binary_utils.compress_files(
            files_to_compress,
            archive_path,
            compression_level=6
        )

        assert compress_result is not None, "Compression must succeed"
        assert compress_result['success'], "Compression must be successful"
        assert os.path.exists(archive_path), "Archive must be created"
        assert compress_result['compressed_size'] < compress_result['original_size'], \
            "Compressed size should be smaller"

        # Extract files
        extract_dir = os.path.join(test_directory, 'extracted')
        extract_result = binary_utils.extract_archive(
            archive_path,
            extract_dir
        )

        assert extract_result is not None, "Extraction must succeed"
        assert extract_result['success'], "Extraction must be successful"
        assert extract_result['files_extracted'] == len(files_to_compress), \
            "All files must be extracted"

        # Verify extracted files
        for original_file in files_to_compress:
            filename = os.path.basename(original_file)
            extracted_file = os.path.join(extract_dir, filename)
            assert os.path.exists(extracted_file), f"Extracted file {filename} must exist"

            # Compare content
            with open(original_file, 'rb') as f1:
                original_data = f1.read()
            with open(extracted_file, 'rb') as f2:
                extracted_data = f2.read()

            assert original_data == extracted_data, f"Extracted {filename} must match original"

    def test_real_file_metadata_operations(self, test_binary_content: bytes, test_directory: str, app_context: AppContext) -> None:
        """Test REAL file metadata operations."""
        system_utils = SystemUtils()
        binary_utils = BinaryUtils()

        metadata_file = os.path.join(test_directory, 'metadata_test.exe')
        with open(metadata_file, 'wb') as f:
            f.write(test_binary_content)

        # Get comprehensive metadata
        metadata = system_utils.get_file_metadata(metadata_file)
        assert metadata is not None, "Metadata retrieval must succeed"
        assert 'basic_info' in metadata, "Must have basic info"
        assert 'extended_info' in metadata, "Must have extended info"
        assert 'security_info' in metadata, "Must have security info"

        basic_info = metadata['basic_info']
        assert 'name' in basic_info, "Must have filename"
        assert 'size' in basic_info, "Must have size"
        assert 'created' in basic_info, "Must have creation time"
        assert 'modified' in basic_info, "Must have modification time"
        assert 'accessed' in basic_info, "Must have access time"

        # Test alternate data streams (Windows)
        if os.name == 'nt':
            ads_result = system_utils.check_alternate_data_streams(metadata_file)
            assert ads_result is not None, "ADS check must return result"
            assert 'has_ads' in ads_result, "Must indicate ADS presence"

        # Get file entropy
        entropy_result = binary_utils.calculate_file_entropy(metadata_file)
        assert entropy_result is not None, "Entropy calculation must succeed"
        assert 'entropy' in entropy_result, "Must have entropy value"
        assert 0 <= entropy_result['entropy'] <= 8, "Entropy must be in valid range"
        assert 'entropy_map' in entropy_result, "Must have entropy map"

        # Check file type
        type_result = binary_utils.identify_file_type(metadata_file)
        assert type_result is not None, "File type identification must succeed"
        assert 'type' in type_result, "Must identify type"
        assert type_result['type'] == 'PE', "Must identify as PE file"
        assert 'confidence' in type_result, "Must have confidence score"
