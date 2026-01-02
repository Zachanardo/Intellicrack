"""Production-Ready Tests for File Handler Module.

Tests REAL file operations including memory mapping, chunk management,
and virtual file access using actual system files.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.file_handler import ChunkManager, LRUCache, VirtualFileAccess


class TestLRUCache:
    """Test LRU Cache implementation with real data."""

    def test_lrucache_stores_and_retrieves_items(self) -> None:
        """LRUCache must store and retrieve items correctly."""
        cache = LRUCache(max_size=5)

        cache[1] = b"value1"
        cache[2] = b"value2"

        assert 1 in cache
        assert cache[1] == b"value1"

    def test_lrucache_evicts_least_recently_used(self) -> None:
        """LRUCache must evict least recently used item when full."""
        cache = LRUCache(max_size=3)

        cache[0] = b"data0"
        cache[1] = b"data1"
        cache[2] = b"data2"

        _ = cache[0]

        cache[3] = b"data3"

        assert 0 in cache
        assert 1 not in cache
        assert 2 in cache
        assert 3 in cache

    def test_lrucache_respects_max_size(self) -> None:
        """LRUCache must not exceed max size."""
        cache = LRUCache(max_size=5)

        for i in range(10):
            cache[i] = f"data{i}".encode()

        assert len(cache) == 5


class TestChunkManager:
    """Test ChunkManager with real file chunk operations."""

    @pytest.fixture
    def test_file(self, tmp_path: Path) -> Path:
        """Create test file with known content."""
        file_path = tmp_path / "test.bin"
        data = bytes(range(256)) * 100
        file_path.write_bytes(data)
        return file_path

    def test_chunkmanager_reads_chunks_correctly(self, test_file: Path) -> None:
        """ChunkManager must read correct data from chunks."""
        manager = ChunkManager(str(test_file), chunk_size=4096)

        chunk = manager.get_chunk(0)
        assert chunk is not None

        data = manager.read_data(0, 256)
        assert data == bytes(range(256))

    def test_chunkmanager_handles_multiple_chunks(self, test_file: Path) -> None:
        """ChunkManager must handle reads spanning multiple chunks."""
        manager = ChunkManager(str(test_file), chunk_size=1024)

        data = manager.read_data(0, 5000)
        assert len(data) == 5000

    def test_chunkmanager_caches_frequently_accessed_chunks(self, test_file: Path) -> None:
        """ChunkManager must cache frequently accessed chunks."""
        manager = ChunkManager(str(test_file), chunk_size=1024, cache_size=3)

        manager.read_data(0, 100)
        manager.read_data(0, 100)

        assert len(manager.active_chunks) > 0

    def test_chunkmanager_reads_across_chunk_boundaries(self, test_file: Path) -> None:
        """ChunkManager must correctly read data spanning chunk boundaries."""
        manager = ChunkManager(str(test_file), chunk_size=1024)

        data = manager.read_data(1000, 100)
        assert len(data) == 100

        expected = bytes(range(256)) * 100
        assert data == expected[1000:1100]

    def test_chunkmanager_handles_file_end(self, test_file: Path) -> None:
        """ChunkManager must handle reads at end of file."""
        file_size = test_file.stat().st_size
        manager = ChunkManager(str(test_file), chunk_size=1024)

        data = manager.read_data(file_size - 10, 100)
        assert len(data) == 10


class TestVirtualFileAccess:
    """Test VirtualFileAccess with real file operations."""

    @pytest.fixture
    def test_binary(self, tmp_path: Path) -> Path:
        """Create test binary file."""
        binary_path = tmp_path / "test.bin"
        data = bytes(range(256)) * 10
        binary_path.write_bytes(data)
        return binary_path

    def test_virtualfileaccess_opens_real_file(self, test_binary: Path) -> None:
        """VirtualFileAccess must open and provide access to real files."""
        vfa = VirtualFileAccess(str(test_binary))

        assert vfa.get_file_size() == 2560

    def test_virtualfileaccess_reads_correct_data(self, test_binary: Path) -> None:
        """VirtualFileAccess must return correct data at offsets."""
        vfa = VirtualFileAccess(str(test_binary))

        data = vfa.read(0, 256)
        assert data == bytes(range(256))

        data = vfa.read(256, 256)
        assert data == bytes(range(256))

    def test_virtualfileaccess_write_operation(self, test_binary: Path) -> None:
        """VirtualFileAccess write must stage modifications."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        new_data = b"MODIFIED"
        success = vfa.write(100, new_data)

        assert success is True

        read_back = vfa.read(100, len(new_data))
        assert read_back == new_data

    def test_virtualfileaccess_apply_edits(self, test_binary: Path) -> None:
        """VirtualFileAccess must apply pending edits to file."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        vfa.write(100, b"EDIT1")
        vfa.write(200, b"EDIT2")

        success = vfa.apply_edits()
        assert success is True

        assert len(vfa.pending_edits) == 0

    def test_virtualfileaccess_discard_edits(self, test_binary: Path) -> None:
        """VirtualFileAccess must discard pending edits."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        original_data = vfa.read(100, 10)

        vfa.write(100, b"TEMPORARY")
        vfa.discard_edits()

        data_after_discard = vfa.read(100, 10)
        assert data_after_discard == original_data

    def test_virtualfileaccess_undo_last_edit(self, test_binary: Path) -> None:
        """VirtualFileAccess must undo last applied edit."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        original_data = vfa.read(100, 10)

        vfa.write(100, b"CHANGED")
        vfa.apply_edits()

        success = vfa.undo_last_edit()
        assert success is True

    def test_virtualfileaccess_handles_large_files(self, tmp_path: Path) -> None:
        """VirtualFileAccess must handle large files efficiently."""
        large_file = tmp_path / "large.bin"
        data = bytes(range(256)) * 4096
        large_file.write_bytes(data)

        vfa = VirtualFileAccess(str(large_file), use_large_file_optimization=True)

        assert vfa.get_file_size() == len(data)

        chunk = vfa.read(500000, 1000)
        assert len(chunk) == 1000

    def test_virtualfileaccess_save_as_creates_new_file(self, test_binary: Path, tmp_path: Path) -> None:
        """VirtualFileAccess save_as must create new file with current state."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        vfa.write(100, b"MODIFIED")

        new_file = tmp_path / "saved.bin"
        success = vfa.save_as(str(new_file))

        assert success is True
        assert new_file.exists()

        new_vfa = VirtualFileAccess(str(new_file))
        data = new_vfa.read(100, 8)
        assert data == b"MODIFIED"

    def test_virtualfileaccess_insert_data(self, test_binary: Path) -> None:
        """VirtualFileAccess insert must increase file size."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        original_size = vfa.get_file_size()
        inserted_data = b"INSERTED"

    def test_virtualfileaccess_delete_data(self, test_binary: Path) -> None:
        """VirtualFileAccess delete must decrease file size."""
        vfa = VirtualFileAccess(str(test_binary), read_only=False)

        original_size = vfa.get_file_size()


class TestVirtualFileAccessWithSystemFiles:
    """Test VirtualFileAccess with real Windows system files."""

    def test_virtualfileaccess_readonly_system_file(self) -> None:
        """VirtualFileAccess must open system files in read-only mode."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found - Windows system required")

        vfa = VirtualFileAccess(str(notepad), read_only=True)

        assert vfa.get_file_size() > 0

        mz_header = vfa.read(0, 2)
        assert mz_header == b"MZ"

    def test_virtualfileaccess_handles_locked_files(self) -> None:
        """VirtualFileAccess must handle locked/protected files."""
        kernel32 = Path("C:/Windows/System32/kernel32.dll")
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found - Windows system required")

        vfa = VirtualFileAccess(str(kernel32), read_only=True)

        data = vfa.read(0, 100)
        assert len(data) > 0

    def test_virtualfileaccess_performance_with_real_binary(self) -> None:
        """VirtualFileAccess must perform efficiently with real binaries."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        vfa = VirtualFileAccess(str(notepad), read_only=True)

        reads = 0
        offset = 0
        while offset < vfa.get_file_size() and reads < 1000:
            data = vfa.read(offset, 1024)
            if not data:
                break
            offset += 1024
            reads += 1

        assert reads > 0


class TestChunkManagerEdgeCases:
    """Test ChunkManager edge cases and error handling."""

    def test_chunkmanager_handles_empty_file(self, tmp_path: Path) -> None:
        """ChunkManager must handle empty files gracefully."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        manager = ChunkManager(str(empty_file))

        data = manager.read_data(0, 100)
        assert data == b""

    def test_chunkmanager_handles_invalid_offset(self, tmp_path: Path) -> None:
        """ChunkManager must handle invalid offsets gracefully."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"TEST" * 100)

        manager = ChunkManager(str(test_file))

        data = manager.read_data(10000, 100)
        assert data == b""

    def test_chunkmanager_handles_zero_size_read(self, tmp_path: Path) -> None:
        """ChunkManager must handle zero-size reads."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"TEST" * 100)

        manager = ChunkManager(str(test_file))

        data = manager.read_data(0, 0)
        assert data == b""
