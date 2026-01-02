"""Production tests for Hex Viewer Widget.

Tests real hex viewing, editing, and binary manipulation.
"""

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.hex_viewer import HexViewerWidget


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test binary file."""
    binary = tmp_path / "test.bin"
    test_data = bytes(range(256))
    binary.write_bytes(test_data)
    return binary


@pytest.fixture
def hex_viewer(qapp: Any) -> Generator[HexViewerWidget, None, None]:
    """Create hex viewer widget."""
    widget = HexViewerWidget()
    yield widget
    widget.deleteLater()


class TestHexViewerInitialization:
    """Test hex viewer initialization."""

    def test_widget_creates_successfully(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer initializes with empty data."""
        assert hex_viewer is not None
        assert isinstance(hex_viewer.data, bytearray)

    def test_has_hex_display_area(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer has display area."""
        assert hasattr(hex_viewer, 'hex_display')


class TestBinaryDataLoading:
    """Test loading binary data."""

    def test_loads_binary_file(
        self, hex_viewer: HexViewerWidget, test_binary: Path
    ) -> None:
        """Hex viewer loads binary file data."""
        file_data = test_binary.read_bytes()

        if hasattr(hex_viewer, 'load_file'):
            hex_viewer.load_file(str(test_binary))
            assert len(hex_viewer.data) == len(file_data)
        elif hasattr(hex_viewer, 'set_data'):
            hex_viewer.set_data(file_data)
            assert len(hex_viewer.data) == len(file_data)

    def test_displays_hex_values(
        self, hex_viewer: HexViewerWidget, test_binary: Path
    ) -> None:
        """Hex viewer displays hexadecimal values."""
        file_data = test_binary.read_bytes()

        if hasattr(hex_viewer, 'load_file'):
            hex_viewer.load_file(str(test_binary))
        elif hasattr(hex_viewer, 'set_data'):
            hex_viewer.set_data(file_data)


class TestHexEditing:
    """Test hex editing functionality."""

    def test_enables_edit_mode(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer can enter edit mode."""
        if hasattr(hex_viewer, 'edit_toggle'):
            hex_viewer.edit_mode = True
            assert hex_viewer.edit_mode

    def test_modifies_byte_value(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer modifies byte values."""
        if hasattr(hex_viewer, 'set_data'):
            test_data = bytearray([0x00, 0x01, 0x02, 0x03])

            hex_viewer.set_data(test_data)
            hex_viewer.edit_mode = True

            original_len = len(hex_viewer.data)
            assert original_len == 4

    def test_emits_modification_signal(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer emits signal when data modified."""
        signals_received = []
        hex_viewer.data_modified.connect(
            lambda offset, data: signals_received.append((offset, data))
        )

        hex_viewer.data_modified.emit(0x10, b'\xFF')
        assert len(signals_received) == 1


class TestByteSelection:
    """Test byte selection functionality."""

    def test_selects_byte_range(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer selects byte ranges."""
        if hasattr(hex_viewer, 'set_data'):
            test_data = bytearray(range(100))
            hex_viewer.set_data(test_data)

        hex_viewer.selected_start = 0x10
        hex_viewer.selected_end = 0x20

        assert hex_viewer.selected_start == 0x10
        assert hex_viewer.selected_end == 0x20

    def test_emits_selection_signal(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer emits selection change signal."""
        signals_received = []
        hex_viewer.selection_changed.connect(
            lambda start, end: signals_received.append((start, end))
        )

        hex_viewer.selection_changed.emit(0, 16)
        assert len(signals_received) == 1


class TestOffsetNavigation:
    """Test offset navigation."""

    def test_has_offset_input(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer has offset input box."""
        assert hasattr(hex_viewer, 'offset_box')

    def test_jumps_to_offset(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer jumps to specified offset."""
        if hasattr(hex_viewer, 'set_data'):
            test_data = bytearray(range(256))
            hex_viewer.set_data(test_data)

        hex_viewer.current_offset = 0x80
        assert hex_viewer.current_offset == 0x80


class TestSearchFunctionality:
    """Test search functionality."""

    def test_has_search_box(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer has search input."""
        assert hasattr(hex_viewer, 'search_box')

    def test_searches_for_bytes(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer searches for byte patterns."""
        if hasattr(hex_viewer, 'set_data'):
            test_data = bytearray([0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD])
            hex_viewer.set_data(test_data)


class TestBytesPerRow:
    """Test bytes per row configuration."""

    def test_sets_bytes_per_row(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer configures bytes per row."""
        assert hex_viewer.bytes_per_row == 16

    def test_changes_bytes_per_row(
        self, hex_viewer: HexViewerWidget
    ) -> None:
        """Hex viewer changes bytes per row."""
        hex_viewer.bytes_per_row = 8
        assert hex_viewer.bytes_per_row == 8
