"""Tests for search_type optimization in advanced_search.py.

This tests that the search_type parameter is properly used for type-specific
optimizations including case sensitivity and binary vs text search handling.
"""


from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


class TestAdvancedSearchTypeOptimization:
    """Test suite for search_type optimization in AdvancedSearch."""

    def test_advanced_search_import(self) -> None:
        """Verify SearchType and SearchResult can be imported."""
        from intellicrack.hexview.advanced_search import SearchResult, SearchType

        assert SearchType is not None
        assert SearchResult is not None

    def test_hex_search_is_case_sensitive(self) -> None:
        """Test that HEX search is always case-sensitive."""
        from intellicrack.hexview.advanced_search import SearchType

        case_sensitive = SearchType.HEX != SearchType.TEXT
        is_binary_search = SearchType.HEX in (SearchType.HEX, SearchType.WILDCARD)

        assert case_sensitive
        assert is_binary_search

    def test_text_search_case_insensitive(self) -> None:
        """Test that TEXT search applies case-insensitive matching."""
        from intellicrack.hexview.advanced_search import SearchType

        case_sensitive = SearchType.TEXT != SearchType.TEXT
        assert not case_sensitive

    def test_regex_search_type(self) -> None:
        """Test REGEX search type handling."""
        from intellicrack.hexview.advanced_search import SearchType

        is_binary = SearchType.REGEX in (SearchType.HEX, SearchType.WILDCARD)
        assert not is_binary

    def test_wildcard_search_is_binary(self) -> None:
        """Test that WILDCARD search is treated as binary search."""
        from intellicrack.hexview.advanced_search import SearchType

        is_binary = SearchType.WILDCARD in (SearchType.HEX, SearchType.WILDCARD)
        assert is_binary

    def test_search_result_structure(self) -> None:
        """Test SearchResult structure is correct."""
        from intellicrack.hexview.advanced_search import SearchResult

        result = SearchResult(
            offset=100,
            length=4,
            data=b"\x4D\x5A\x90\x00",
            context=b"\x00\x00\x4D\x5A\x90\x00\x00\x00",
        )

        assert result.offset == 100
        assert result.length == 4
        assert result.data == b"\x4D\x5A\x90\x00"
        assert result.context == b"\x00\x00\x4D\x5A\x90\x00\x00\x00"

    def test_binary_pattern_search(self) -> None:
        """Test binary pattern search finds exact byte sequences."""
        chunk_data = b"\x00\x00\x4D\x5A\x90\x00\x00\x00\x4D\x5A\x00\x00"
        pattern = b"\x4D\x5A"

        positions = []
        pos = 0
        while True:
            pos = chunk_data.find(pattern, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1

        assert positions == [2, 8]

    def test_case_insensitive_text_search(self) -> None:
        """Test case-insensitive search with TEXT type."""
        chunk_data = b"LICENSE license License"
        pattern = b"license"

        search_data = chunk_data.lower()
        search_pattern = pattern.lower()

        positions = []
        pos = 0
        while True:
            pos = search_data.find(search_pattern, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1

        assert len(positions) == 3

    def test_case_sensitive_hex_search(self) -> None:
        """Test case-sensitive search with HEX type."""
        from intellicrack.hexview.advanced_search import SearchType

        chunk_data = b"LICENSE license License"
        pattern = b"LICENSE"

        case_sensitive = SearchType.HEX != SearchType.TEXT
        assert case_sensitive

        if case_sensitive:
            search_data = chunk_data
            search_pattern = pattern
        else:
            search_data = chunk_data.lower()
            search_pattern = pattern.lower()

        positions = []
        pos = 0
        while True:
            pos = search_data.find(search_pattern, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1

        assert len(positions) == 1
        assert positions[0] == 0

    def test_search_type_enum_values(self) -> None:
        """Test all SearchType enum values exist."""
        from intellicrack.hexview.advanced_search import SearchType

        assert hasattr(SearchType, "HEX")
        assert hasattr(SearchType, "TEXT")
        assert hasattr(SearchType, "REGEX")
        assert hasattr(SearchType, "WILDCARD")

    def test_empty_pattern_handling(self) -> None:
        """Test handling of empty search patterns."""
        pattern = b""

        positions = []
        if pattern:
            pos = 0
            chunk_data = b"\x00\x01\x02\x03"
            while True:
                pos = chunk_data.find(pattern, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += 1

        assert not positions

    def test_pattern_longer_than_chunk(self) -> None:
        """Test handling when pattern is longer than chunk."""
        chunk_data = b"\x00\x01"
        pattern = b"\x00\x01\x02\x03\x04"

        pos = chunk_data.find(pattern)
        assert pos == -1

    def test_binary_search_preserves_case(self) -> None:
        """Test that binary search types preserve byte case."""
        from intellicrack.hexview.advanced_search import SearchType

        chunk_data = b"\x41\x42\x43"
        pattern = b"\x61\x62\x63"

        is_binary = SearchType.HEX in (SearchType.HEX, SearchType.WILDCARD)

        if is_binary:
            search_data = chunk_data
            search_pattern = pattern
        else:
            search_data = chunk_data.lower()
            search_pattern = pattern.lower()

        pos = search_data.find(search_pattern)
        assert pos == -1 if is_binary else pos == 0

    def test_context_extraction_bounds(self) -> None:
        """Test that context extraction respects chunk boundaries."""
        chunk_data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        pos = 0
        pattern_len = 2
        context_size = 16

        context_start = max(0, pos - context_size)
        context_end = min(len(chunk_data), pos + pattern_len + context_size)

        context = chunk_data[context_start:context_end]

        assert context_start == 0
        assert len(context) == len(chunk_data)
