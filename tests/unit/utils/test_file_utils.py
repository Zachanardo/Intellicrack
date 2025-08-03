"""
Unit tests for File Utils with REAL file operations.
Tests REAL file handling, binary operations, and format detection.
NO MOCKS - ALL TESTS USE REAL FILES AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import tempfile
import os
import struct

from intellicrack.utils.file_utils import FileUtils
from tests.base_test import IntellicrackTestBase


class TestFileUtils(IntellicrackTestBase):
    """Test file utilities with REAL file operations."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real file utils."""
        self.utils = FileUtils()
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def test_file_type_detection(self):
        """Test file type detection with real files."""
        # Create test files
        exe_file = self.temp_dir / "test.exe"
        exe_file.write_bytes(b'MZ' + b'\x90' * 58 + b'\x00\x00\x00\x00')  # PE header
        
        elf_file = self.temp_dir / "test.elf"
        elf_file.write_bytes(b'\x7fELF' + b'\x01' * 12)  # ELF header
        
        text_file = self.temp_dir / "test.txt"
        text_file.write_text("This is a text file")
        
        # Test detection
        exe_type = self.utils.detect_file_type(exe_file)
        self.assert_real_output(exe_type)
        assert exe_type == 'PE'
        
        elf_type = self.utils.detect_file_type(elf_file)
        assert elf_type == 'ELF'
        
        text_type = self.utils.detect_file_type(text_file)
        assert text_type == 'TEXT'
        
    def test_safe_file_operations(self):
        """Test safe file read/write operations."""
        test_file = self.temp_dir / "safe_test.bin"
        test_data = b"Test data \x00\xFF\xAA\x55"
        
        # Safe write
        result = self.utils.safe_write(test_file, test_data)
        
        self.assert_real_output(result)
        assert result == True
        assert test_file.exists()
        assert test_file.read_bytes() == test_data
        
        # Safe read
        read_data = self.utils.safe_read(test_file)
        assert read_data == test_data
        
        # Test non-existent file
        no_file = self.temp_dir / "nonexistent.bin"
        read_result = self.utils.safe_read(no_file)
        assert read_result is None
        
    def test_binary_patching(self):
        """Test binary file patching."""
        # Create test binary
        binary_file = self.temp_dir / "patch_test.bin"
        original_data = b'\x00' * 100 + b'ORIGINAL' + b'\x00' * 100
        binary_file.write_bytes(original_data)
        
        # Patch binary
        patch_data = b'PATCHED!'
        result = self.utils.patch_binary(
            binary_file,
            offset=100,
            data=patch_data
        )
        
        self.assert_real_output(result)
        assert result == True
        
        # Verify patch
        patched_data = binary_file.read_bytes()
        assert patched_data[100:108] == patch_data
        assert len(patched_data) == len(original_data)
        
    def test_file_hashing(self):
        """Test file hashing operations."""
        # Create test file
        test_file = self.temp_dir / "hash_test.dat"
        test_file.write_bytes(b"Test content for hashing")
        
        # Calculate hashes
        md5_hash = self.utils.hash_file(test_file, algorithm='md5')
        sha256_hash = self.utils.hash_file(test_file, algorithm='sha256')
        
        self.assert_real_output(md5_hash)
        self.assert_real_output(sha256_hash)
        
        assert len(md5_hash) == 32  # MD5 hex length
        assert len(sha256_hash) == 64  # SHA256 hex length
        
        # Same file should produce same hash
        md5_hash2 = self.utils.hash_file(test_file, algorithm='md5')
        assert md5_hash == md5_hash2
        
    def test_file_backup_restore(self):
        """Test file backup and restore."""
        # Create original file
        original_file = self.temp_dir / "original.dat"
        original_data = b"Original file content"
        original_file.write_bytes(original_data)
        
        # Backup file
        backup_path = self.utils.backup_file(original_file)
        
        self.assert_real_output(backup_path)
        assert backup_path.exists()
        assert backup_path.read_bytes() == original_data
        
        # Modify original
        original_file.write_bytes(b"Modified content")
        
        # Restore from backup
        result = self.utils.restore_file(backup_path, original_file)
        assert result == True
        assert original_file.read_bytes() == original_data
        
    def test_temp_file_management(self):
        """Test temporary file creation and cleanup."""
        # Create temp file
        temp_file = self.utils.create_temp_file(
            suffix='.tmp',
            prefix='test_',
            data=b'Temporary data'
        )
        
        self.assert_real_output(temp_file)
        assert temp_file.exists()
        assert temp_file.read_bytes() == b'Temporary data'
        assert temp_file.name.startswith('test_')
        assert temp_file.name.endswith('.tmp')
        
        # Auto cleanup
        self.utils.cleanup_temp_files()
        assert not temp_file.exists()
        
    def test_file_compression(self):
        """Test file compression/decompression."""
        # Create test file
        test_file = self.temp_dir / "compress_test.txt"
        test_data = b"This is test data to compress " * 100
        test_file.write_bytes(test_data)
        
        # Compress file
        compressed = self.utils.compress_file(test_file, format='gzip')
        
        self.assert_real_output(compressed)
        assert compressed.exists()
        assert compressed.stat().st_size < test_file.stat().st_size
        
        # Decompress file
        decompressed = self.utils.decompress_file(compressed, format='gzip')
        assert decompressed.read_bytes() == test_data
        
    def test_file_splitting_joining(self):
        """Test file splitting and joining."""
        # Create large file
        large_file = self.temp_dir / "large.dat"
        large_data = os.urandom(1024 * 1024)  # 1MB
        large_file.write_bytes(large_data)
        
        # Split file
        parts = self.utils.split_file(large_file, chunk_size=256 * 1024)  # 256KB chunks
        
        self.assert_real_output(parts)
        assert len(parts) == 4  # 1MB / 256KB = 4 parts
        
        for part in parts:
            assert part.exists()
            assert part.stat().st_size <= 256 * 1024
            
        # Join files
        joined_file = self.temp_dir / "joined.dat"
        result = self.utils.join_files(parts, joined_file)
        
        assert result == True
        assert joined_file.read_bytes() == large_data
        
    def test_file_search(self):
        """Test file search functionality."""
        # Create test directory structure
        subdir = self.temp_dir / "subdir"
        subdir.mkdir()
        
        (self.temp_dir / "file1.txt").write_text("content")
        (self.temp_dir / "file2.exe").write_bytes(b"MZ")
        (subdir / "file3.txt").write_text("more content")
        (subdir / "file4.dat").write_bytes(b"data")
        
        # Search by extension
        txt_files = self.utils.find_files(self.temp_dir, pattern="*.txt")
        
        self.assert_real_output(txt_files)
        assert len(txt_files) == 2
        assert all(f.suffix == '.txt' for f in txt_files)
        
        # Search by name pattern
        numbered_files = self.utils.find_files(self.temp_dir, pattern="file[0-9].*")
        assert len(numbered_files) == 4
        
    def test_file_metadata(self):
        """Test file metadata extraction."""
        # Create test file
        test_file = self.temp_dir / "metadata_test.bin"
        test_file.write_bytes(b"Test content")
        
        # Get metadata
        metadata = self.utils.get_file_metadata(test_file)
        
        self.assert_real_output(metadata)
        assert 'size' in metadata
        assert 'created' in metadata
        assert 'modified' in metadata
        assert 'permissions' in metadata
        assert metadata['size'] == 12
        
    def test_binary_comparison(self):
        """Test binary file comparison."""
        # Create files
        file1 = self.temp_dir / "file1.bin"
        file2 = self.temp_dir / "file2.bin"
        file3 = self.temp_dir / "file3.bin"
        
        data1 = b"Same content here"
        data2 = b"Same content here"
        data3 = b"Different content"
        
        file1.write_bytes(data1)
        file2.write_bytes(data2)
        file3.write_bytes(data3)
        
        # Compare files
        result = self.utils.compare_files(file1, file2)
        self.assert_real_output(result)
        assert result['identical'] == True
        assert result['differences'] == []
        
        result = self.utils.compare_files(file1, file3)
        assert result['identical'] == False
        assert len(result['differences']) > 0
        assert result['differences'][0]['offset'] == 0
        
    def test_hex_dump(self):
        """Test hex dump generation."""
        # Create binary file
        binary_file = self.temp_dir / "hexdump.bin"
        binary_data = b'Hello\x00\x01\x02\x03\xFFWorld!'
        binary_file.write_bytes(binary_data)
        
        # Generate hex dump
        hexdump = self.utils.hex_dump(binary_file, bytes_per_line=8)
        
        self.assert_real_output(hexdump)
        assert '48 65 6C 6C 6F' in hexdump  # "Hello"
        assert '00 01 02 03 FF' in hexdump  # Binary bytes
        assert 'Hello' in hexdump  # ASCII representation
        
    def test_file_permissions(self):
        """Test file permission operations."""
        # Create test file
        test_file = self.temp_dir / "perm_test.txt"
        test_file.write_text("Permission test")
        
        # Get permissions
        perms = self.utils.get_permissions(test_file)
        
        self.assert_real_output(perms)
        assert 'read' in perms
        assert 'write' in perms
        assert perms['read'] == True
        
        # Set permissions (platform dependent)
        if os.name != 'nt':  # Unix-like
            self.utils.set_permissions(test_file, mode=0o600)
            perms = self.utils.get_permissions(test_file)
            assert perms['mode'] == 0o600
            
    def test_file_locking(self):
        """Test file locking mechanism."""
        # Create test file
        test_file = self.temp_dir / "lock_test.txt"
        test_file.write_text("Lock test")
        
        # Acquire lock
        lock = self.utils.acquire_lock(test_file)
        
        self.assert_real_output(lock)
        assert lock is not None
        
        # Try to acquire again (should fail or block)
        lock2 = self.utils.try_acquire_lock(test_file, timeout=0.1)
        assert lock2 is None  # Should fail
        
        # Release lock
        self.utils.release_lock(lock)
        
        # Now should succeed
        lock3 = self.utils.try_acquire_lock(test_file, timeout=0.1)
        assert lock3 is not None
        self.utils.release_lock(lock3)
        
    def test_file_monitoring(self):
        """Test file change monitoring."""
        # Create test file
        test_file = self.temp_dir / "monitor_test.txt"
        test_file.write_text("Initial content")
        
        # Start monitoring
        initial_state = self.utils.get_file_state(test_file)
        
        # Modify file
        import time
        time.sleep(0.1)
        test_file.write_text("Modified content")
        
        # Check for changes
        changes = self.utils.detect_changes(test_file, initial_state)
        
        self.assert_real_output(changes)
        assert changes['modified'] == True
        assert changes['size_changed'] == True
        assert changes['content_changed'] == True
        
    def test_secure_delete(self):
        """Test secure file deletion."""
        # Create sensitive file
        sensitive_file = self.temp_dir / "sensitive.dat"
        sensitive_data = b"Sensitive information"
        sensitive_file.write_bytes(sensitive_data)
        
        # Secure delete
        result = self.utils.secure_delete(sensitive_file, passes=3)
        
        self.assert_real_output(result)
        assert result == True
        assert not sensitive_file.exists()
        
    def test_file_carving(self):
        """Test file carving from binary data."""
        # Create binary with embedded files
        container = self.temp_dir / "container.bin"
        
        # Embed JPEG signature
        jpeg_data = b'\xFF\xD8\xFF\xE0' + b'JFIF' + b'\x00' * 100 + b'\xFF\xD9'
        # Embed PNG signature
        png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
        # Embed ZIP signature
        zip_data = b'PK\x03\x04' + b'\x00' * 30
        
        container_data = b'\x00' * 100 + jpeg_data + b'\x00' * 50 + png_data + b'\x00' * 20 + zip_data
        container.write_bytes(container_data)
        
        # Carve files
        carved = self.utils.carve_files(container)
        
        self.assert_real_output(carved)
        assert len(carved) >= 2  # At least JPEG and PNG
        
        types_found = [c['type'] for c in carved]
        assert 'JPEG' in types_found
        assert 'PNG' in types_found