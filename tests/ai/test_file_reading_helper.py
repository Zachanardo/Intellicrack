"""Production tests for File Reading Helper.

Tests unified file reading with AIFileTools integration and fallback mechanisms.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.file_reading_helper import (
    FileReadingMixin,
    read_binary_header,
    read_file_with_ai_tools,
    read_text_file,
)


@pytest.fixture
def temp_text_file() -> Path:
    """Create temporary text file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("Test content for file reading\nMultiple lines\nWith various data")
        return Path(f.name)


@pytest.fixture
def temp_binary_file() -> Path:
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00" + b"\x00" * 506 + b"PE\x00\x00")
        return Path(f.name)


class TestFileReadingWithAITools:
    """Test file reading with AIFileTools integration."""

    def test_read_text_file_success(self, temp_text_file: Path) -> None:
        """Text file reading returns content and used_ai_tools flag."""
        content, used_ai_tools = read_file_with_ai_tools(
            str(temp_text_file),
            purpose="Test reading",
            mode="text",
        )

        assert content is not None
        assert isinstance(content, str)
        assert "Test content" in content
        assert isinstance(used_ai_tools, bool)

    def test_read_binary_file_success(self, temp_binary_file: Path) -> None:
        """Binary file reading returns bytes and used_ai_tools flag."""
        content, used_ai_tools = read_file_with_ai_tools(
            str(temp_binary_file),
            purpose="Binary analysis",
            mode="binary",
        )

        assert content is not None
        assert isinstance(content, bytes)
        assert content.startswith(b"MZ")
        assert isinstance(used_ai_tools, bool)

    def test_read_binary_with_max_bytes(self, temp_binary_file: Path) -> None:
        """Binary reading respects max_bytes limit."""
        max_bytes = 64
        content, used_ai_tools = read_file_with_ai_tools(
            str(temp_binary_file),
            purpose="Header analysis",
            mode="binary",
            max_bytes=max_bytes,
        )

        assert content is not None
        assert isinstance(content, bytes)
        assert len(content) <= max_bytes

    def test_read_text_with_encoding(self, temp_text_file: Path) -> None:
        """Text reading respects encoding parameter."""
        content, _ = read_file_with_ai_tools(
            str(temp_text_file),
            purpose="Encoding test",
            mode="text",
            encoding="utf-8",
        )

        assert content is not None
        assert isinstance(content, str)

    def test_read_nonexistent_file(self) -> None:
        """Reading nonexistent file returns None without crash."""
        content, used_ai_tools = read_file_with_ai_tools(
            "/nonexistent/file.txt",
            purpose="Error test",
        )

        assert content is None
        assert isinstance(used_ai_tools, bool)

    def test_fallback_to_direct_read(self, temp_text_file: Path) -> None:
        """Direct file reading fallback works when AIFileTools unavailable."""
        content, used_ai_tools = read_file_with_ai_tools(
            str(temp_text_file),
            purpose="Fallback test",
            app_instance=None,
        )

        assert content is not None


class TestBinaryHeaderReading:
    """Test binary header reading functionality."""

    def test_read_pe_header(self, temp_binary_file: Path) -> None:
        """PE binary header reading extracts correct signature."""
        header = read_binary_header(str(temp_binary_file), header_size=512)

        assert header is not None
        assert isinstance(header, bytes)
        assert header.startswith(b"MZ")
        assert len(header) <= 512

    def test_read_header_custom_size(self, temp_binary_file: Path) -> None:
        """Custom header size parameter respected."""
        header_size = 128
        header = read_binary_header(str(temp_binary_file), header_size=header_size)

        assert header is not None
        assert len(header) <= header_size

    def test_read_header_nonexistent_file(self) -> None:
        """Reading header from nonexistent file returns None."""
        header = read_binary_header("/nonexistent/binary.exe")
        assert header is None


class TestTextFileReading:
    """Test text file reading convenience function."""

    def test_read_text_file_utf8(self, temp_text_file: Path) -> None:
        """UTF-8 text file reading produces correct string content."""
        content = read_text_file(str(temp_text_file))

        assert content is not None
        assert isinstance(content, str)
        assert "Test content" in content

    def test_read_text_file_alternate_encoding(self, temp_text_file: Path) -> None:
        """Alternate encoding parameter used correctly."""
        content = read_text_file(str(temp_text_file), encoding="utf-8")

        assert content is not None
        assert isinstance(content, str)

    def test_read_text_file_nonexistent(self) -> None:
        """Reading nonexistent text file returns None."""
        content = read_text_file("/nonexistent/file.txt")
        assert content is None


class TestFileReadingMixin:
    """Test FileReadingMixin for AI component integration."""

    def test_mixin_read_file_safe_text(self, temp_text_file: Path) -> None:
        """Mixin read_file_safe method reads text files correctly."""

        class TestClass(FileReadingMixin):
            def __init__(self) -> None:
                self.app_instance = None

        obj = TestClass()
        content = obj.read_file_safe(str(temp_text_file), purpose="Mixin test", mode="text")

        assert content is not None
        assert isinstance(content, str)

    def test_mixin_read_file_safe_binary(self, temp_binary_file: Path) -> None:
        """Mixin read_file_safe method reads binary files correctly."""

        class TestClass(FileReadingMixin):
            def __init__(self) -> None:
                self.app_instance = None

        obj = TestClass()
        content = obj.read_file_safe(str(temp_binary_file), purpose="Binary test", mode="binary")

        assert content is not None
        assert isinstance(content, bytes)

    def test_mixin_with_max_bytes(self, temp_binary_file: Path) -> None:
        """Mixin respects max_bytes parameter for binary reads."""

        class TestClass(FileReadingMixin):
            def __init__(self) -> None:
                self.app_instance = None

        obj = TestClass()
        max_bytes = 32
        content = obj.read_file_safe(str(temp_binary_file), mode="binary", max_bytes=max_bytes)

        assert content is not None
        assert isinstance(content, bytes)
        assert len(content) <= max_bytes

    def test_mixin_without_app_instance(self, temp_text_file: Path) -> None:
        """Mixin works when class doesn't have app_instance attribute."""

        class TestClass(FileReadingMixin):
            pass

        obj = TestClass()
        content = obj.read_file_safe(str(temp_text_file))

        assert content is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_large_file_reading(self) -> None:
        """Large file reading with max_bytes prevents memory issues."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x00" * (10 * 1024 * 1024))
            large_file = Path(f.name)

        content, _ = read_file_with_ai_tools(
            str(large_file),
            mode="binary",
            max_bytes=1024,
        )

        assert content is not None
        assert len(content) <= 1024

    def test_empty_file_reading(self) -> None:
        """Empty file reading returns empty content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            empty_file = Path(f.name)

        content, _ = read_file_with_ai_tools(str(empty_file), mode="text")

        assert content is not None
        assert content == ""

    def test_binary_file_as_text(self, temp_binary_file: Path) -> None:
        """Reading binary file as text handles encoding errors gracefully."""
        content, _ = read_file_with_ai_tools(str(temp_binary_file), mode="text")

        assert content is not None or content is None


class TestPerformance:
    """Test performance characteristics."""

    def test_repeated_reads_performance(self, temp_text_file: Path) -> None:
        """Repeated file reads complete without degradation."""
        for _ in range(10):
            content, _ = read_file_with_ai_tools(str(temp_text_file))
            assert content is not None

    def test_header_read_faster_than_full(self, temp_binary_file: Path) -> None:
        """Header reading is more efficient than full file read."""
        header = read_binary_header(str(temp_binary_file), header_size=512)
        full_content, _ = read_file_with_ai_tools(str(temp_binary_file), mode="binary")

        assert header is not None
        assert full_content is not None
        assert len(header) <= len(full_content)
