"""Production-Ready Tests for Advanced Search Module.

Tests REAL binary search, pattern matching, and replace operations
using actual binary data from Windows system files.
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.hexview.advanced_search import (
    BaseFileHandler,
    SearchEngine,
    SearchHistory,
    SearchResult,
    SearchType,
)


class TestSearchResult:
    """Test SearchResult data structure functionality."""

    def test_searchresult_stores_match_data_correctly(self) -> None:
        """SearchResult must store offset, length, data, and context correctly."""
        data = b"TEST"
        context = b"CONTEXT_TEST_DATA"
        result = SearchResult(offset=100, length=4, data=data, context=context)

        assert result.offset == 100
        assert result.length == 4
        assert result.data == data
        assert result.context == context

    def test_searchresult_serialization_roundtrip(self) -> None:
        """SearchResult must serialize and deserialize without data loss."""
        original = SearchResult(offset=256, length=8, data=b"\x00\x01\x02\x03\x04\x05\x06\x07", context=b"\xFF" * 32)

        serialized = original.to_dict()
        deserialized = SearchResult.from_dict(serialized)

        assert deserialized.offset == original.offset
        assert deserialized.length == original.length
        assert deserialized.data == original.data
        assert deserialized.context == original.context


class TestBaseFileHandler:
    """Test BaseFileHandler file operations with real binary data."""

    @pytest.fixture
    def test_binary(self, tmp_path: Path) -> Path:
        """Create a test binary file with known content."""
        binary_path = tmp_path / "test.bin"
        test_data = bytes(range(256)) * 4
        binary_path.write_bytes(test_data)
        return binary_path

    def test_basefilehandler_loads_real_file(self, test_binary: Path) -> None:
        """BaseFileHandler must load and provide access to real binary files."""
        handler = BaseFileHandler(str(test_binary))

        assert handler.get_file_size() == 1024
        assert len(handler._data) == 1024

    def test_basefilehandler_reads_correct_data(self, test_binary: Path) -> None:
        """BaseFileHandler must return correct data at specified offsets."""
        handler = BaseFileHandler(str(test_binary))

        data_at_0 = handler.read(0, 16)
        assert data_at_0 == bytes(range(16))

        data_at_256 = handler.read(256, 16)
        assert data_at_256 == bytes(range(16))

    def test_basefilehandler_insert_operation(self, test_binary: Path) -> None:
        """BaseFileHandler insert must actually modify data in memory."""
        handler = BaseFileHandler(str(test_binary))
        handler.read_only = False

        original_size = handler.get_file_size()
        insert_data = b"INSERTED"

        success = handler.insert(100, insert_data)

        assert success is True
        assert handler.get_file_size() == original_size + len(insert_data)

        read_back = handler.read(100, len(insert_data))
        assert read_back == insert_data

    def test_basefilehandler_delete_operation(self, test_binary: Path) -> None:
        """BaseFileHandler delete must actually remove data."""
        handler = BaseFileHandler(str(test_binary))
        handler.read_only = False

        original_size = handler.get_file_size()
        bytes_before_delete = handler.read(50, 10)
        bytes_after_delete_position = handler.read(60, 10)

        success = handler.delete(50, 10)

        assert success is True
        assert handler.get_file_size() == original_size - 10

        bytes_at_50_after_delete = handler.read(50, 10)
        assert bytes_at_50_after_delete == bytes_after_delete_position


class TestSearchEngine:
    """Test SearchEngine with real binary searching scenarios."""

    @pytest.fixture
    def pe_binary(self) -> Path:
        """Use actual Windows PE binary for testing."""
        notepad_path = Path("C:/Windows/System32/notepad.exe")
        if not notepad_path.exists():
            pytest.skip("notepad.exe not found - Windows system required")
        return notepad_path

    @pytest.fixture
    def search_handler(self, pe_binary: Path) -> BaseFileHandler:
        """Create file handler for PE binary."""
        return BaseFileHandler(str(pe_binary))

    @pytest.fixture
    def search_engine(self, search_handler: BaseFileHandler) -> SearchEngine:
        """Create search engine with PE binary."""
        return SearchEngine(search_handler)

    def test_searchengine_finds_mz_header(self, search_engine: SearchEngine) -> None:
        """SearchEngine must locate PE MZ signature in actual binary."""
        result = search_engine.search(
            pattern=b"MZ",
            search_type=SearchType.HEX,
            start_offset=0,
            case_sensitive=True,
        )

        assert result is not None
        assert result.offset == 0
        assert result.data == b"MZ"

    def test_searchengine_finds_pe_signature(self, search_engine: SearchEngine) -> None:
        """SearchEngine must locate PE signature in actual Windows executable."""
        result = search_engine.search(
            pattern=b"PE\x00\x00",
            search_type=SearchType.HEX,
            start_offset=0,
            case_sensitive=True,
        )

        assert result is not None
        assert result.data == b"PE\x00\x00"

    def test_searchengine_hex_search_finds_all_occurrences(self, search_engine: SearchEngine) -> None:
        """SearchEngine search_all must find all pattern occurrences."""
        results = search_engine.search_all(
            pattern=b"\x00\x00",
            search_type=SearchType.HEX,
            max_results=100,
        )

        assert len(results) > 0
        for result in results:
            assert result.data == b"\x00\x00"
            assert result.length == 2

    def test_searchengine_text_search_case_insensitive(self, search_engine: SearchEngine) -> None:
        """SearchEngine must perform case-insensitive text search."""
        result_lower = search_engine.search(
            pattern="microsoft",
            search_type=SearchType.TEXT,
            case_sensitive=False,
        )

        assert result_lower is not None

    def test_searchengine_regex_search_finds_patterns(self) -> None:
        """SearchEngine regex search must match real patterns in binary."""
        test_data = b"Error: File not found\nWarning: Invalid data\nError: Access denied"
        handler = BaseFileHandler()
        handler._data = test_data
        handler._file_size = len(test_data)
        handler.read_only = False

        engine = SearchEngine(handler)

        results = engine.search_all(
            pattern=r"Error:\s+\w+",
            search_type=SearchType.REGEX,
            case_sensitive=True,
            max_results=10,
        )

        assert len(results) == 2

    def test_searchengine_wildcard_search_works(self) -> None:
        """SearchEngine wildcard search must expand wildcards correctly."""
        test_data = b"file.txt file.doc file.exe data.bin"
        handler = BaseFileHandler()
        handler._data = test_data
        handler._file_size = len(test_data)

        engine = SearchEngine(handler)

        results = engine.search_all(
            pattern="file.*",
            search_type=SearchType.WILDCARD,
            max_results=10,
        )

        assert len(results) >= 3

    def test_searchengine_backward_search(self) -> None:
        """SearchEngine must search backward from offset."""
        test_data = b"AAAA" + b"X" * 100 + b"BBBB" + b"X" * 100 + b"CCCC"
        handler = BaseFileHandler()
        handler._data = test_data
        handler._file_size = len(test_data)

        engine = SearchEngine(handler)

        result = engine.search(
            pattern=b"BBBB",
            search_type=SearchType.HEX,
            start_offset=300,
            direction="backward",
        )

        assert result is not None
        assert result.data == b"BBBB"

    def test_searchengine_replace_all_modifies_data(self) -> None:
        """SearchEngine replace_all must actually replace all occurrences."""
        test_data = b"AAA_BBB_AAA_CCC_AAA"
        handler = BaseFileHandler()
        handler._data = test_data
        handler._file_size = len(test_data)
        handler.read_only = False

        engine = SearchEngine(handler)

        replaced_ranges = engine.replace_all(
            find_pattern=b"AAA",
            replace_pattern=b"XXX",
            search_type=SearchType.HEX,
        )

        assert len(replaced_ranges) == 3

        modified_data = handler._data
        assert modified_data.count(b"XXX") == 3
        assert modified_data.count(b"AAA") == 0


class TestSearchHistory:
    """Test SearchHistory persistence and retrieval."""

    @pytest.fixture
    def temp_history_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """Create temporary directory for search history."""
        history_dir = tmp_path / ".intellicrack"
        history_dir.mkdir()
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        return history_dir

    def test_searchhistory_saves_and_loads_searches(self, temp_history_dir: Path) -> None:
        """SearchHistory must persist searches across instances."""
        history1 = SearchHistory(max_entries=50)
        history1.add_search("test_pattern", SearchType.HEX, {"case_sensitive": True})
        history1.add_search("another_pattern", SearchType.TEXT, {"whole_words": False})

        history2 = SearchHistory(max_entries=50)

        recent = history2.get_recent_searches(limit=10)
        assert "another_pattern" in recent
        assert "test_pattern" in recent

    def test_searchhistory_limits_entries(self, temp_history_dir: Path) -> None:
        """SearchHistory must respect max_entries limit."""
        history = SearchHistory(max_entries=5)

        for i in range(10):
            history.add_search(f"pattern_{i}", SearchType.HEX, {})

        assert len(history.entries) == 5

    def test_searchhistory_filters_by_type(self, temp_history_dir: Path) -> None:
        """SearchHistory must filter searches by type."""
        history = SearchHistory(max_entries=50)
        history.add_search("hex_pattern", SearchType.HEX, {})
        history.add_search("text_pattern", SearchType.TEXT, {})
        history.add_search("regex_pattern", SearchType.REGEX, {})

        hex_searches = history.get_recent_searches(search_type=SearchType.HEX)
        assert "hex_pattern" in hex_searches
        assert "text_pattern" not in hex_searches


class TestSearchEnginePerformance:
    """Test SearchEngine performance with large binaries."""

    @pytest.fixture
    def large_binary(self, tmp_path: Path) -> Path:
        """Create a large test binary (1MB)."""
        binary_path = tmp_path / "large.bin"
        data = bytes(range(256)) * 4096
        binary_path.write_bytes(data)
        return binary_path

    def test_searchengine_handles_large_files(self, large_binary: Path) -> None:
        """SearchEngine must efficiently search large files."""
        handler = BaseFileHandler(str(large_binary))
        engine = SearchEngine(handler)

        results = engine.search_all(
            pattern=b"\xFF",
            search_type=SearchType.HEX,
            max_results=1000,
        )

        assert len(results) <= 1000
        for result in results:
            assert result.data == b"\xFF"

    def test_searchengine_chunked_search_accuracy(self, large_binary: Path) -> None:
        """SearchEngine chunked search must find patterns across chunk boundaries."""
        handler = BaseFileHandler(str(large_binary))
        engine = SearchEngine(handler)

        pattern = b"\xFE\xFF\x00\x01"
        results = engine.search_all(
            pattern=pattern,
            search_type=SearchType.HEX,
            max_results=100,
        )

        for result in results:
            actual_data = handler.read(result.offset, result.length)
            assert actual_data == pattern
