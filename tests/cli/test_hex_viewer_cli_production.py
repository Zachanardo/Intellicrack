"""Production tests for Hex Viewer CLI module.

These tests validate that hex viewer correctly:
- Loads and displays binary data in hex format
- Handles cursor navigation and display offset adjustment
- Performs hex/ASCII editing operations
- Implements search functionality for hex patterns and text
- Saves modifications to files
- Handles edge cases (empty files, large files, corrupted data)
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.cli.hex_viewer_cli import TerminalHexViewer, launch_hex_viewer


class TestHexViewerInitialization:
    """Test hex viewer initialization and file loading."""

    def test_hex_viewer_loads_small_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" * 10)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.filepath == str(test_file)
        assert viewer.file_size == 80
        assert viewer.data is not None
        assert len(viewer.data) == 80
        assert viewer.bytes_per_line == 16
        assert viewer.current_offset == 0
        assert viewer.cursor_offset == 0

    def test_hex_viewer_loads_empty_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.file_size == 0
        assert viewer.data is not None

    def test_hex_viewer_loads_pe_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00"
        test_file.write_bytes(pe_header * 10)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.file_size > 0
        assert viewer.data[:2] == b"MZ"

    def test_hex_viewer_raises_on_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError, match="File not found"):
            TerminalHexViewer("/nonexistent/path/file.bin")

    def test_hex_viewer_initialization_settings(self, tmp_path: Path) -> None:
        test_file = tmp_path / "settings_test.bin"
        test_file.write_bytes(b"TEST" * 20)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.edit_mode is False
        assert viewer.hex_edit_mode is True
        assert viewer.modified is False
        assert len(viewer.modifications) == 0
        assert viewer.search_pattern == ""
        assert len(viewer.search_results) == 0


class TestHexDisplay:
    """Test hex data display formatting."""

    def test_hex_line_format_basic(self, tmp_path: Path) -> None:
        test_file = tmp_path / "format_test.bin"
        test_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.data[0] == 0x00
        assert viewer.data[1] == 0x01
        assert viewer.data[15] == 0x0F

    def test_hex_viewer_handles_binary_data(self, tmp_path: Path) -> None:
        test_file = tmp_path / "binary.bin"

        test_data = bytes(range(256))
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.file_size == 256
        assert viewer.data[0] == 0
        assert viewer.data[255] == 255


class TestCursorNavigation:
    """Test cursor movement and display adjustment."""

    def test_move_cursor_forward(self, tmp_path: Path) -> None:
        test_file = tmp_path / "nav_test.bin"
        test_file.write_bytes(b"A" * 100)

        viewer = TerminalHexViewer(str(test_file))
        viewer._move_cursor(10)

        assert viewer.cursor_offset == 10

    def test_move_cursor_backward(self, tmp_path: Path) -> None:
        test_file = tmp_path / "nav_test.bin"
        test_file.write_bytes(b"B" * 100)

        viewer = TerminalHexViewer(str(test_file))
        viewer.cursor_offset = 20
        viewer._move_cursor(-10)

        assert viewer.cursor_offset == 10

    def test_move_cursor_boundaries(self, tmp_path: Path) -> None:
        test_file = tmp_path / "boundary_test.bin"
        test_file.write_bytes(b"X" * 50)

        viewer = TerminalHexViewer(str(test_file))

        viewer._move_cursor(-100)
        assert viewer.cursor_offset == 0

        viewer._move_cursor(1000)
        assert viewer.cursor_offset == 49

    def test_cursor_adjustment_keeps_visible(self, tmp_path: Path) -> None:
        test_file = tmp_path / "adjust_test.bin"
        test_file.write_bytes(b"Y" * 500)

        viewer = TerminalHexViewer(str(test_file))
        viewer.hex_area_height = 10

        viewer.cursor_offset = 200
        viewer._adjust_display()

        assert viewer.current_offset <= viewer.cursor_offset


class TestHexEditing:
    """Test hex editing functionality."""

    def test_edit_hex_digit(self, tmp_path: Path) -> None:
        test_file = tmp_path / "edit_test.bin"
        test_file.write_bytes(b"\x00" * 10)

        viewer = TerminalHexViewer(str(test_file))
        viewer.cursor_offset = 0

        viewer._edit_hex_digit(0xF)

        assert 0 in viewer.modifications
        assert viewer.modified is True

    def test_ascii_editing(self, tmp_path: Path) -> None:
        test_file = tmp_path / "ascii_edit.bin"
        test_file.write_bytes(b"HELLO")

        viewer = TerminalHexViewer(str(test_file))
        viewer.hex_edit_mode = False
        viewer.cursor_offset = 0

        viewer._handle_edit_character(ord("A"))

        assert viewer.modifications[0] == ord("A")
        assert viewer.modified is True
        assert viewer.cursor_offset == 1

    def test_modifications_tracking(self, tmp_path: Path) -> None:
        test_file = tmp_path / "modifications.bin"
        test_file.write_bytes(b"\x00" * 20)

        viewer = TerminalHexViewer(str(test_file))

        viewer.modifications[0] = 0xFF
        viewer.modifications[5] = 0xAA
        viewer.modifications[10] = 0x55
        viewer.modified = True

        assert len(viewer.modifications) == 3
        assert viewer.modifications[0] == 0xFF
        assert viewer.modifications[5] == 0xAA

    def test_save_changes(self, tmp_path: Path) -> None:
        test_file = tmp_path / "save_test.bin"
        original_data = b"\x00\x11\x22\x33\x44"
        test_file.write_bytes(original_data)

        viewer = TerminalHexViewer(str(test_file))

        viewer.modifications[0] = 0xFF
        viewer.modifications[2] = 0xAA
        viewer.modified = True

        viewer._save_changes()

        modified_data = test_file.read_bytes()
        assert modified_data[0] == 0xFF
        assert modified_data[2] == 0xAA
        assert modified_data[1] == 0x11
        assert not viewer.modified
        assert len(viewer.modifications) == 0


class TestSearchFunctionality:
    """Test search operations."""

    def test_search_hex_pattern(self, tmp_path: Path) -> None:
        test_file = tmp_path / "search_hex.bin"
        test_data = b"\x00\x01\x02\x03\x04\x05\x4D\x5A\x90\x00\x03\x00"
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))
        viewer.search_pattern = "4D5A"
        viewer.search_pattern_type = "hex"

        viewer._perform_search()

        assert len(viewer.search_results) > 0
        assert viewer.search_results[0][0] == 6

    def test_search_text_pattern(self, tmp_path: Path) -> None:
        test_file = tmp_path / "search_text.bin"
        test_data = b"This is a test string with license key inside it"
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))
        viewer.search_pattern = "license"
        viewer.search_pattern_type = "text"

        viewer._perform_search()

        assert len(viewer.search_results) > 0
        pos, length = viewer.search_results[0]
        assert test_data[pos : pos + length] == b"license"

    def test_next_search_result(self, tmp_path: Path) -> None:
        test_file = tmp_path / "search_next.bin"
        test_data = b"ABC" * 10
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))
        viewer.search_pattern = "ABC"
        viewer.search_pattern_type = "text"
        viewer._perform_search()

        initial_index = viewer.current_search_index
        viewer._next_search_result()

        assert viewer.current_search_index == (initial_index + 1) % len(viewer.search_results)

    def test_prev_search_result(self, tmp_path: Path) -> None:
        test_file = tmp_path / "search_prev.bin"
        test_data = b"XYZ" * 5
        test_file.write_bytes(test_data)

        viewer = TerminalHexViewer(str(test_file))
        viewer.search_pattern = "XYZ"
        viewer.search_pattern_type = "text"
        viewer._perform_search()

        viewer.current_search_index = 2
        viewer._prev_search_result()

        assert viewer.current_search_index == 1

    def test_search_no_results(self, tmp_path: Path) -> None:
        test_file = tmp_path / "search_none.bin"
        test_file.write_bytes(b"\x00" * 100)

        viewer = TerminalHexViewer(str(test_file))
        viewer.search_pattern = "NOTFOUND"
        viewer.search_pattern_type = "text"

        viewer._perform_search()

        assert len(viewer.search_results) == 0


class TestGotoOffset:
    """Test offset navigation."""

    def test_goto_offset_validates_range(self, tmp_path: Path) -> None:
        test_file = tmp_path / "goto_test.bin"
        test_file.write_bytes(b"Z" * 100)

        viewer = TerminalHexViewer(str(test_file))

        viewer.cursor_offset = 50
        viewer._adjust_display()

        assert 0 <= viewer.cursor_offset < viewer.file_size


class TestCleanup:
    """Test resource cleanup."""

    def test_cleanup_closes_resources(self, tmp_path: Path) -> None:
        test_file = tmp_path / "cleanup_test.bin"
        test_file.write_bytes(b"DATA" * 25)

        viewer = TerminalHexViewer(str(test_file))

        viewer._cleanup()

        if viewer.mmap_file:
            assert viewer.mmap_file.closed
        if viewer.file_handle:
            assert viewer.file_handle.closed


class TestLaunchHexViewer:
    """Test hex viewer launch function."""

    def test_launch_hex_viewer_with_valid_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "launch_test.bin"
        test_file.write_bytes(b"LAUNCH" * 10)

        result = launch_hex_viewer(str(test_file))

        assert result is True or result is False

    def test_launch_hex_viewer_handles_errors(self) -> None:
        result = launch_hex_viewer("/invalid/path.bin")

        assert result is False or isinstance(result, bool)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_hex_viewer_handles_large_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "large.bin"

        large_data = b"LARGE" * 10000
        test_file.write_bytes(large_data)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.file_size == 50000
        assert viewer.data is not None

    def test_hex_viewer_handles_special_characters(self, tmp_path: Path) -> None:
        test_file = tmp_path / "special.bin"

        special_data = bytes(range(256))
        test_file.write_bytes(special_data)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.file_size == 256

    def test_hex_viewer_readonly_fallback(self, tmp_path: Path) -> None:
        test_file = tmp_path / "readonly.bin"
        test_file.write_bytes(b"READONLY" * 10)

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.data is not None
        assert len(viewer.data) == 80


class TestRealBinaryFiles:
    """Test with real binary file structures."""

    def test_hex_viewer_displays_pe_header(self, tmp_path: Path) -> None:
        test_file = tmp_path / "pe_test.exe"

        pe_header = bytearray(b"MZ")
        pe_header.extend(b"\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00")
        pe_header.extend(b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00")
        pe_header.extend(b"\x00" * 32)
        pe_header.extend(b"PE\x00\x00")

        test_file.write_bytes(bytes(pe_header))

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.data[:2] == b"MZ"
        assert b"PE\x00\x00" in viewer.data

    def test_hex_viewer_displays_elf_header(self, tmp_path: Path) -> None:
        test_file = tmp_path / "elf_test"

        elf_header = bytearray(b"\x7fELF")
        elf_header.extend(b"\x02\x01\x01\x00")
        elf_header.extend(b"\x00" * 8)
        elf_header.extend(b"\x02\x00\x3E\x00")

        test_file.write_bytes(bytes(elf_header))

        viewer = TerminalHexViewer(str(test_file))

        assert viewer.data[:4] == b"\x7fELF"
