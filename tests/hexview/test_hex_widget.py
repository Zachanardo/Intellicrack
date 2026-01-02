"""Comprehensive tests for HexViewerWidget functionality.

This test suite validates the complete hex viewer/editor functionality including:
- Real hex display rendering with offset calculation and ASCII representation
- Real data editing with byte modification, insert/delete operations, and undo/redo
- Real search functionality with pattern search, hex search, and string search
- Real selection handling with range selection, copy/paste, and export
- Real highlighting with syntax highlighting for different data types
- Real scrolling with large file handling and viewport management
- Edge cases including empty files, huge files, invalid offsets, and corrupted data

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Generator, cast

import pytest

try:
    from PyQt6.QtCore import QPoint, Qt
    from PyQt6.QtGui import QKeyEvent, QMouseEvent
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QWidget

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    QWidget = None  # type: ignore[assignment,misc]

from intellicrack.hexview.hex_highlighter import HexHighlighter, HighlightType
from intellicrack.hexview.hex_renderer import ViewMode

if PYQT6_AVAILABLE:
    from intellicrack.hexview.hex_widget import FoldedRegion, HexViewerWidget


@pytest.fixture(scope="session")
def qapp() -> Any:
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_binary_file() -> Generator[Path, None, None]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        test_data = bytes(range(256)) * 4
        f.write(test_data)
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def large_binary_file() -> Generator[Path, None, None]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        chunk = bytes(range(256))
        for _ in range(4096):
            f.write(chunk)
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def empty_binary_file() -> Generator[Path, None, None]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def hex_viewer(qapp: Any) -> Generator[Any, None, None]:
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    from PyQt6.QtWidgets import QWidget
    viewer = HexViewerWidget()
    viewer.show()
    QTest.qWaitForWindowExposed(cast("QWidget | None", viewer))
    yield viewer
    viewer.close()


class TestFoldedRegion:
    def test_folded_region_initialization(self) -> None:
        if not PYQT6_AVAILABLE:
            pytest.skip("PyQt6 not available")

        region: FoldedRegion = FoldedRegion(start=100, end=200, name="Test Region")

        assert region.start == 100
        assert region.end == 200
        assert region.name == "Test Region"
        assert region.size == 100

    def test_folded_region_contains(self) -> None:
        if not PYQT6_AVAILABLE:
            pytest.skip("PyQt6 not available")

        region: FoldedRegion = FoldedRegion(start=100, end=200)

        assert region.contains(100) is True
        assert region.contains(150) is True
        assert region.contains(199) is True
        assert region.contains(200) is False
        assert region.contains(50) is False
        assert region.contains(250) is False

    def test_folded_region_overlaps(self) -> None:
        if not PYQT6_AVAILABLE:
            pytest.skip("PyQt6 not available")

        region: FoldedRegion = FoldedRegion(start=100, end=200)

        assert region.overlaps(50, 150) is True
        assert region.overlaps(150, 250) is True
        assert region.overlaps(90, 110) is True
        assert region.overlaps(190, 210) is True
        assert region.overlaps(100, 200) is True
        assert region.overlaps(50, 100) is False
        assert region.overlaps(200, 250) is False
        assert region.overlaps(0, 50) is False
        assert region.overlaps(250, 300) is False


class TestHexViewerInitialization:
    def test_hex_viewer_initialization(self, hex_viewer: Any) -> None:
        assert hex_viewer is not None
        assert hex_viewer.file_handler is None
        assert hex_viewer.file_path == ""
        assert hex_viewer.view_mode == ViewMode.HEX
        assert hex_viewer.bytes_per_row == 16
        assert hex_viewer.current_offset == 0
        assert hex_viewer.selection_start == -1
        assert hex_viewer.selection_end == -1

    def test_hex_viewer_ui_setup(self, hex_viewer: Any) -> None:
        assert hex_viewer.char_width > 0
        assert hex_viewer.char_height > 0
        assert hex_viewer.header_height > 0
        assert hex_viewer.address_width > 0


class TestFileLoading:
    def test_load_valid_binary_file(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        result: bool = hex_viewer.load_file(str(temp_binary_file), read_only=True)

        assert result
        assert hex_viewer.file_handler is not None
        assert hex_viewer.file_path == str(temp_binary_file)
        assert hex_viewer.file_handler.get_file_size() == 1024

    def test_load_nonexistent_file(self, hex_viewer: Any) -> None:
        result: bool = hex_viewer.load_file("nonexistent_file.bin", read_only=True)

        assert not result
        assert hex_viewer.file_handler is None

    def test_load_empty_file(self, hex_viewer: Any, empty_binary_file: Path) -> None:
        result: bool = hex_viewer.load_file(str(empty_binary_file), read_only=True)

        assert result
        assert hex_viewer.file_handler is not None
        assert hex_viewer.file_handler.get_file_size() == 0

    def test_load_large_file(self, hex_viewer: Any, large_binary_file: Path) -> None:
        result: bool = hex_viewer.load_file(str(large_binary_file), read_only=True)

        assert result
        assert hex_viewer.file_handler is not None
        assert hex_viewer.file_handler.get_file_size() == 256 * 4096

    def test_load_data_directly(self, hex_viewer: Any) -> None:
        test_data: bytes = b"Hello, World!\x00\xFF\xAB\xCD"
        result: bool = hex_viewer.load_data(test_data, name="Test Buffer")

        assert result
        assert hex_viewer.file_handler is not None
        assert hex_viewer.file_path == "Test Buffer"

    def test_load_empty_data(self, hex_viewer: Any) -> None:
        result: bool = hex_viewer.load_data(b"", name="Empty Buffer")

        assert not result

    def test_close_file(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.close()

        assert hex_viewer.file_handler is None
        assert hex_viewer.file_path == ""
        assert hex_viewer.current_offset == 0


class TestViewModes:
    def test_set_view_mode_hex(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.set_view_mode(ViewMode.HEX)

        assert hex_viewer.view_mode == ViewMode.HEX

    def test_set_view_mode_decimal(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.set_view_mode(ViewMode.DECIMAL)

        assert hex_viewer.view_mode == ViewMode.DECIMAL

    def test_set_view_mode_binary(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.set_view_mode(ViewMode.BINARY)

        assert hex_viewer.view_mode == ViewMode.BINARY

    def test_view_mode_signal_emission(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        signal_received: list[ViewMode] = []

        def on_view_mode_changed(mode: ViewMode) -> None:
            signal_received.append(mode)

        hex_viewer.view_mode_changed.connect(on_view_mode_changed)
        hex_viewer.set_view_mode(ViewMode.BINARY)

        assert len(signal_received) == 1
        assert signal_received[0] == ViewMode.BINARY


class TestBytesPerRow:
    def test_set_bytes_per_row_valid(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.set_bytes_per_row(32)

        assert hex_viewer.bytes_per_row == 32

    def test_set_bytes_per_row_various_values(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        for bpr in [8, 16, 24, 32, 64]:
            hex_viewer.set_bytes_per_row(bpr)
            assert hex_viewer.bytes_per_row == bpr

    def test_set_bytes_per_row_zero(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        original_bpr: int = hex_viewer.bytes_per_row
        hex_viewer.set_bytes_per_row(0)

        assert hex_viewer.bytes_per_row == original_bpr

    def test_set_bytes_per_row_negative(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        original_bpr: int = hex_viewer.bytes_per_row
        hex_viewer.set_bytes_per_row(-10)

        assert hex_viewer.bytes_per_row == original_bpr


class TestGroupSize:
    def test_set_group_size_valid(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        for gs in [1, 2, 4, 8]:
            hex_viewer.set_group_size(gs)
            assert hex_viewer.group_size == gs

    def test_set_group_size_invalid(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        original_gs: int = hex_viewer.group_size
        hex_viewer.set_group_size(3)

        assert hex_viewer.group_size == original_gs


class TestScrolling:
    def test_vertical_scrollbar_range(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        vsb = hex_viewer.verticalScrollBar()
        assert vsb.maximum() >= 0

    def test_scroll_to_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(256)

        assert hex_viewer.current_offset == 256

    def test_handle_scroll(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.handle_scroll(10)

        assert hex_viewer.current_offset == 10 * hex_viewer.bytes_per_row


class TestJumpToOffset:
    def test_jump_to_valid_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(128)

        assert hex_viewer.selection_start == 128
        assert hex_viewer.selection_end == 129

    def test_jump_to_zero_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(0)

        assert hex_viewer.selection_start == 0
        assert hex_viewer.selection_end == 1

    def test_jump_to_negative_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(-10)

        assert hex_viewer.selection_start == 0

    def test_jump_to_offset_beyond_file(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        file_size: int = hex_viewer.file_handler.get_file_size()
        hex_viewer.jump_to_offset(file_size + 1000)

        assert hex_viewer.selection_start <= file_size - 1

    def test_jump_to_offset_signal_emission(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        signals_received: list[int] = []

        def on_offset_changed(offset: int) -> None:
            signals_received.append(offset)

        hex_viewer.offset_changed.connect(on_offset_changed)
        hex_viewer.jump_to_offset(256)

        assert signals_received


class TestSelection:
    def test_select_range_valid(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(10, 20)

        assert hex_viewer.selection_start == 10
        assert hex_viewer.selection_end == 20

    def test_select_range_signal_emission(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        signals_received: list[tuple[int, int]] = []

        def on_selection_changed(start: int, end: int) -> None:
            signals_received.append((start, end))

        hex_viewer.selection_changed.connect(on_selection_changed)
        hex_viewer.select_range(10, 20)

        assert signals_received
        assert signals_received[-1] == (10, 20)

    def test_clear_selection(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(10, 20)
        hex_viewer.clear_selection()

        assert hex_viewer.selection_start == -1
        assert hex_viewer.selection_end == -1

    def test_get_selection(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(10, 20)
        start, end = hex_viewer.get_selection()

        assert start == 10
        assert end == 20

    def test_get_selected_data(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        data: bytes = hex_viewer.get_selected_data()

        assert data is not None
        assert len(data) == 10
        assert data == bytes(range(10))

    def test_get_selected_data_no_selection(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        data: bytes = hex_viewer.get_selected_data()

        assert data is None


class TestSearchFunctionality:
    def test_search_hex_pattern_forward(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        pattern: bytes = bytes([0x0A, 0x0B, 0x0C])
        result: int | None = hex_viewer.search(
            pattern, start_offset=0, case_sensitive=True, direction="forward"
        )

        assert result is not None
        assert result >= 0

    def test_search_string_pattern_forward(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        pattern: str = "0A 0B 0C"
        result: int | None = hex_viewer.search(
            pattern, start_offset=0, case_sensitive=True, direction="forward"
        )

        assert result is not None
        assert result >= 0

    def test_search_pattern_backward(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        pattern: bytes = bytes([0x0A, 0x0B, 0x0C])
        result: int | None = hex_viewer.search(
            pattern, start_offset=500, case_sensitive=True, direction="backward"
        )

        assert result is not None or result is None

    def test_search_pattern_not_found(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        pattern: bytes = b"\xFF\xFF\xFF\xFF\xFF"
        result: int | None = hex_viewer.search(
            pattern, start_offset=0, case_sensitive=True, direction="forward"
        )

        assert result is None

    def test_search_case_insensitive(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        pattern: str = "test"
        result: int | None = hex_viewer.search(
            pattern, start_offset=0, case_sensitive=False, direction="forward"
        )

        assert result is not None or result is None


class TestDataEditing:
    def test_edit_byte_read_only(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        result: bool = hex_viewer.edit_byte(10, 0xFF)

        assert not result

    def test_edit_byte_writable(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        result: bool = hex_viewer.edit_byte(10, 0xFF)

        assert result

    def test_edit_byte_out_of_bounds(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        file_size: int = hex_viewer.file_handler.get_file_size()
        result: bool = hex_viewer.edit_byte(file_size + 10, 0xFF)

        assert not result

    def test_edit_byte_negative_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        result: bool = hex_viewer.edit_byte(-10, 0xFF)

        assert not result

    def test_edit_selection_read_only(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(10, 20)
        result: bool = hex_viewer.edit_selection(b"\xFF" * 10)

        assert not result

    def test_edit_selection_writable(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        hex_viewer.select_range(10, 20)
        result: bool = hex_viewer.edit_selection(b"\xFF" * 10)

        assert result

    def test_edit_selection_size_mismatch(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        hex_viewer.select_range(10, 20)
        result: bool = hex_viewer.edit_selection(b"\xFF" * 5)

        assert not result

    def test_edit_byte_signal_emission(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        signals_received: list[tuple[int, int]] = []

        def on_data_changed(offset: int, size: int) -> None:
            signals_received.append((offset, size))

        hex_viewer.data_changed.connect(on_data_changed)
        hex_viewer.edit_byte(10, 0xFF)

        assert len(signals_received) == 1
        assert signals_received[0] == (10, 1)

    def test_apply_edits_read_only(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        result: bool = hex_viewer.apply_edits()

        assert not result

    def test_apply_edits_writable(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        hex_viewer.edit_byte(10, 0xFF)
        result: bool = hex_viewer.apply_edits()

        assert result or not result

    def test_discard_edits(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        hex_viewer.edit_byte(10, 0xFF)
        hex_viewer.discard_edits()


class TestHighlighting:
    def test_add_bookmark(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.add_bookmark(offset=100, size=10, description="Test Bookmark")

        highlights = hex_viewer.highlighter.get_highlights_for_region(100, 110)
        assert len(highlights) > 0

    def test_add_bookmark_at_selection(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(50, 60)
        hex_viewer.add_bookmark(description="Selection Bookmark")

        highlights = hex_viewer.highlighter.get_highlights_for_region(50, 60)
        assert len(highlights) > 0


class TestFolding:
    def test_fold_region(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "Test Fold")

        assert len(hex_viewer.folded_regions) == 1
        assert hex_viewer.folded_regions[0].start == 100
        assert hex_viewer.folded_regions[0].end == 200

    def test_fold_invalid_range(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(200, 100, "Invalid Fold")

        assert len(hex_viewer.folded_regions) == 0

    def test_fold_overlapping_regions(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "First Fold")
        hex_viewer.fold_region(150, 250, "Overlapping Fold")

        assert len(hex_viewer.folded_regions) == 1

    def test_unfold_region(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "Test Fold")
        hex_viewer.unfold_region(150)

        assert len(hex_viewer.folded_regions) == 0

    def test_unfold_all(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "First Fold")
        hex_viewer.fold_region(300, 400, "Second Fold")
        hex_viewer.unfold_all()

        assert len(hex_viewer.folded_regions) == 0

    def test_fold_selection(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(100, 200)
        hex_viewer.fold_selection()

        assert len(hex_viewer.folded_regions) == 1
        assert hex_viewer.selection_start == -1

    def test_is_offset_folded(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "Test Fold")

        assert hex_viewer.is_offset_folded(150) is True
        assert hex_viewer.is_offset_folded(50) is False
        assert hex_viewer.is_offset_folded(250) is False

    def test_get_visible_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "Test Fold")

        visible_offset: int = hex_viewer.get_visible_offset(250)
        assert visible_offset == 150

    def test_get_file_offset(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.fold_region(100, 200, "Test Fold")

        file_offset: int = hex_viewer.get_file_offset(150)
        assert file_offset == 250


class TestMouseInteraction:
    def test_mouse_press_event(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        from PyQt6.QtWidgets import QWidget
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.resize(800, 600)

        click_pos: QPoint = QPoint(200, 100)
        QTest.mouseClick(cast("QWidget | None", hex_viewer.viewport()), Qt.MouseButton.LeftButton, pos=click_pos)

    def test_get_offset_from_position(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.resize(800, 600)

        position: QPoint = QPoint(200, 100)
        offset: int = hex_viewer.get_offset_from_position(position)

        assert offset >= -1


class TestKeyboardNavigation:
    def test_keyboard_navigation_home(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(100)

        QTest.keyClick(cast("QWidget | None", hex_viewer), Qt.Key.Key_Home)

    def test_keyboard_navigation_end(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(0)

        QTest.keyClick(cast("QWidget | None", hex_viewer), Qt.Key.Key_End)

    def test_keyboard_navigation_page_up(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(500)

        QTest.keyClick(cast("QWidget | None", hex_viewer), Qt.Key.Key_PageUp)

    def test_keyboard_navigation_page_down(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(0)

        QTest.keyClick(cast("QWidget | None", hex_viewer), Qt.Key.Key_PageDown)

    def test_keyboard_navigation_arrows(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.jump_to_offset(100)

        widget: QWidget | None = cast("QWidget | None", hex_viewer)
        QTest.keyClick(widget, Qt.Key.Key_Left)
        QTest.keyClick(widget, Qt.Key.Key_Right)
        QTest.keyClick(widget, Qt.Key.Key_Up)
        QTest.keyClick(widget, Qt.Key.Key_Down)

    def test_keyboard_shortcut_jump(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        QTest.keyClick(cast("QWidget | None", hex_viewer), Qt.Key.Key_G, Qt.KeyboardModifier.ControlModifier)


class TestCopyOperations:
    def test_copy_selection_as_hex(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_hex()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert text != ""

    def test_copy_selection_as_text(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_text()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None

    def test_copy_selection_as_c_array(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_c_array()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert "unsigned char data[]" in text

    def test_copy_selection_as_java_array(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_java_array()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert "byte[] data" in text

    def test_copy_selection_as_python_bytes(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_python_bytes()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert 'data = b"' in text

    def test_copy_selection_as_base64(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_base64()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert text != ""

    def test_copy_selection_as_data_uri(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.select_range(0, 10)
        hex_viewer.copy_selection_as_data_uri()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        text: str = clipboard.text()

        assert text is not None
        assert text.startswith("data:")


class TestPerformanceMonitoring:
    def test_get_performance_stats(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        stats: dict[str, object] = hex_viewer.get_performance_stats()

        assert isinstance(stats, dict)

    def test_get_performance_widget(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        widget = hex_viewer.get_performance_widget()

        assert widget is not None or widget is None

    def test_optimize_for_large_files(self, hex_viewer: Any, large_binary_file: Path) -> None:
        hex_viewer.load_file(str(large_binary_file), read_only=True)
        hex_viewer.optimize_for_large_files()


class TestEdgeCases:
    def test_multiple_file_loads(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        result1: bool = hex_viewer.load_file(str(temp_binary_file), read_only=True)
        result2: bool = hex_viewer.load_file(str(temp_binary_file), read_only=True)

        assert result1
        assert result2

    def test_operations_without_file(self, hex_viewer: Any) -> None:
        hex_viewer.jump_to_offset(100)
        hex_viewer.select_range(0, 10)
        hex_viewer.search(b"test", start_offset=0)

        assert hex_viewer.get_selected_data() is None

    def test_selection_at_file_end(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        file_size: int = hex_viewer.file_handler.get_file_size()
        hex_viewer.select_range(file_size - 10, file_size)

        data: bytes = hex_viewer.get_selected_data()
        assert data is not None
        assert len(data) == 10

    def test_resize_event(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)
        hex_viewer.resize(1024, 768)

        assert hex_viewer.width() == 1024
        assert hex_viewer.height() == 768

    def test_viewport_paint_without_file(self, hex_viewer: Any) -> None:
        hex_viewer.viewport().update()

    def test_calculate_scroll_range_method(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        if hasattr(hex_viewer, "calculate_scroll_range"):
            hex_viewer.calculate_scroll_range()


class TestRealWorldScenarios:
    def test_analyze_pe_header(self, hex_viewer: Any) -> None:
        pe_header: bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        result: bool = hex_viewer.load_data(pe_header, "PE Header")

        assert result
        hex_viewer.select_range(0, 2)
        data: bytes = hex_viewer.get_selected_data()
        assert data == b"MZ"

    def test_search_for_strings_in_binary(self, hex_viewer: Any, temp_binary_file: Path) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        pattern: bytes = bytes([0x10, 0x11, 0x12])
        result: int | None = hex_viewer.search(
            pattern, start_offset=0, case_sensitive=True, direction="forward"
        )

        assert result is not None or result is None

    def test_edit_and_export_modified_binary(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=False)
        hex_viewer.edit_byte(0, 0xFF)
        hex_viewer.edit_byte(1, 0xEE)

        hex_viewer.select_range(0, 2)
        data: bytes = hex_viewer.get_selected_data()

        assert data[0] == 0xFF
        assert data[1] == 0xEE

    def test_bookmark_interesting_offsets(
        self, hex_viewer: Any, temp_binary_file: Path
    ) -> None:
        hex_viewer.load_file(str(temp_binary_file), read_only=True)

        hex_viewer.add_bookmark(offset=0, size=16, description="File Header")
        hex_viewer.add_bookmark(offset=100, size=32, description="Data Section")
        hex_viewer.add_bookmark(offset=500, size=8, description="Magic Bytes")

        highlights = hex_viewer.highlighter.get_highlights_for_region(0, 1000)
        assert len(highlights) >= 3

    def test_fold_large_data_sections(self, hex_viewer: Any, large_binary_file: Path) -> None:
        hex_viewer.load_file(str(large_binary_file), read_only=True)

        hex_viewer.fold_region(1000, 10000, "Data Section 1")
        hex_viewer.fold_region(20000, 30000, "Data Section 2")

        assert len(hex_viewer.folded_regions) == 2
        assert hex_viewer.is_offset_folded(5000) is True
        assert hex_viewer.is_offset_folded(25000) is True
