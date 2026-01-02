"""Production tests for print dialog module.

Tests print output format generation and configuration without mocks,
validating actual print rendering functionality.
"""

from pathlib import Path
from typing import Any, Generator, cast

import pytest
from PyQt6.QtCore import QRectF
from PyQt6.QtGui import QFont, QPainter
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtWidgets import QApplication, QDialog

from intellicrack.hexview.print_dialog import PrintOptionsDialog


class FakeFileHandler:
    """Real test double for file handler."""

    def __init__(self, file_path: str = "test.bin", file_size: int = 1024) -> None:
        self.file_path: str = file_path
        self.file_size: int = file_size
        self._data: bytes = b"\x00" * file_size

    def read_data(self, offset: int, size: int) -> bytes:
        """Read data from file at offset."""
        return self._data[offset : offset + size]

    def set_data(self, data: bytes) -> None:
        """Set internal data for testing."""
        self._data = data
        self.file_size = len(data)


class FakeHexViewer:
    """Real test double for hex viewer."""

    def __init__(
        self,
        file_path: str = "test.bin",
        file_size: int = 1024,
        selection_start: int = -1,
        selection_end: int = -1,
    ) -> None:
        self.selection_start: int = selection_start
        self.selection_end: int = selection_end
        self.file_handler: FakeFileHandler = FakeFileHandler(file_path, file_size)


class FakePainter:
    """Real test double for QPainter."""

    def __init__(self) -> None:
        self.font_set_count: int = 0
        self.draw_text_count: int = 0
        self.set_fonts: list[QFont] = []
        self.drawn_texts: list[tuple[Any, str]] = []

    def setFont(self, font: QFont) -> None:
        """Track font setting."""
        self.font_set_count += 1
        self.set_fonts.append(font)

    def drawText(self, *args: Any) -> None:
        """Track text drawing."""
        self.draw_text_count += 1
        self.drawn_texts.append(args)

    @property
    def called(self) -> bool:
        """Check if any method was called."""
        return self.font_set_count > 0 or self.draw_text_count > 0


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for Qt tests."""
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
    else:
        app = QApplication([])
        yield app


@pytest.fixture
def print_dialog(qapp: QApplication) -> PrintOptionsDialog:
    """Create print options dialog instance."""
    return PrintOptionsDialog()


@pytest.fixture
def fake_hex_viewer() -> FakeHexViewer:
    """Create fake hex viewer with file handler."""
    return FakeHexViewer()


@pytest.fixture
def print_dialog_with_viewer(
    qapp: QApplication, fake_hex_viewer: FakeHexViewer
) -> PrintOptionsDialog:
    """Create print dialog with fake hex viewer."""
    return PrintOptionsDialog(hex_viewer=cast(Any, fake_hex_viewer))


@pytest.fixture
def test_data() -> bytes:
    """Create test binary data."""
    return bytes(range(256)) + b"\x00" * 768


class TestPrintOptionsDialogInitialization:
    """Test print options dialog initialization."""

    def test_dialog_creates_successfully(self, print_dialog: PrintOptionsDialog) -> None:
        """Dialog initializes with all components."""
        assert print_dialog is not None
        assert print_dialog.windowTitle() == "Print Options"
        assert print_dialog.printer is not None
        assert isinstance(print_dialog.printer, QPrinter)

    def test_all_checkboxes_initialized(self, print_dialog: PrintOptionsDialog) -> None:
        """All checkboxes are initialized."""
        assert hasattr(print_dialog, "all_pages_check")
        assert hasattr(print_dialog, "selection_check")
        assert hasattr(print_dialog, "page_range_check")
        assert hasattr(print_dialog, "show_offset_check")
        assert hasattr(print_dialog, "show_ascii_check")
        assert hasattr(print_dialog, "show_grid_check")
        assert hasattr(print_dialog, "show_header_check")
        assert hasattr(print_dialog, "show_footer_check")
        assert hasattr(print_dialog, "use_colors_check")
        assert hasattr(print_dialog, "highlight_selection_check")

    def test_spin_boxes_initialized(self, print_dialog: PrintOptionsDialog) -> None:
        """All spin boxes are initialized."""
        assert hasattr(print_dialog, "from_page_spin")
        assert hasattr(print_dialog, "to_page_spin")
        assert hasattr(print_dialog, "font_size_spin")
        assert hasattr(print_dialog, "bytes_per_row_spin")

    def test_default_values(self, print_dialog: PrintOptionsDialog) -> None:
        """Default values are set correctly."""
        assert print_dialog.all_pages_check.isChecked()
        assert not print_dialog.selection_check.isChecked()
        assert print_dialog.show_offset_check.isChecked()
        assert print_dialog.show_ascii_check.isChecked()
        assert not print_dialog.show_grid_check.isChecked()
        assert print_dialog.show_header_check.isChecked()
        assert print_dialog.show_footer_check.isChecked()
        assert not print_dialog.use_colors_check.isChecked()

    def test_bytes_per_row_default(self, print_dialog: PrintOptionsDialog) -> None:
        """Bytes per row defaults to 16."""
        assert print_dialog.bytes_per_row_spin.value() == 16

    def test_font_defaults(self, print_dialog: PrintOptionsDialog) -> None:
        """Font defaults are set correctly."""
        assert print_dialog.font_size_spin.value() == 10
        assert "Courier" in print_dialog.font_combo.currentFont().family()

    def test_header_footer_defaults(self, print_dialog: PrintOptionsDialog) -> None:
        """Header and footer have default text."""
        assert "%filename%" in print_dialog.header_edit.text()
        assert "%page%" in print_dialog.footer_edit.text()


class TestSelectionHandling:
    """Test selection-based printing."""

    def test_selection_disabled_without_viewer(self, print_dialog: PrintOptionsDialog) -> None:
        """Selection checkbox disabled without hex viewer."""
        assert not print_dialog.selection_check.isEnabled()

    def test_selection_disabled_without_selection(
        self, print_dialog_with_viewer: PrintOptionsDialog
    ) -> None:
        """Selection checkbox disabled without active selection."""
        assert not print_dialog_with_viewer.selection_check.isEnabled()

    def test_selection_enabled_with_selection(self, qapp: QApplication) -> None:
        """Selection checkbox enabled with active selection."""
        fake_viewer = FakeHexViewer(selection_start=100, selection_end=200)
        dialog = PrintOptionsDialog(hex_viewer=cast(Any, fake_viewer))

        assert dialog.selection_check.isEnabled()
        assert "100 bytes" in dialog.selection_check.text()


class TestRangeSelection:
    """Test print range selection logic."""

    def test_all_pages_unchecks_others(self, print_dialog: PrintOptionsDialog) -> None:
        """Selecting all pages unchecks other range options."""
        print_dialog.selection_check.setChecked(True)
        print_dialog.all_pages_check.setChecked(True)
        QApplication.processEvents()

        assert not print_dialog.selection_check.isChecked()
        assert not print_dialog.page_range_check.isChecked()

    def test_page_range_enables_spinboxes(self, print_dialog: PrintOptionsDialog) -> None:
        """Selecting page range enables spin boxes."""
        assert not print_dialog.from_page_spin.isEnabled()
        assert not print_dialog.to_page_spin.isEnabled()

        print_dialog.page_range_check.setChecked(True)
        QApplication.processEvents()

        assert print_dialog.from_page_spin.isEnabled()
        assert print_dialog.to_page_spin.isEnabled()

    def test_page_range_unchecks_others(self, print_dialog: PrintOptionsDialog) -> None:
        """Selecting page range unchecks other options."""
        print_dialog.all_pages_check.setChecked(True)
        print_dialog.page_range_check.setChecked(True)
        QApplication.processEvents()

        assert not print_dialog.all_pages_check.isChecked()


class TestHeaderFooterToggle:
    """Test header and footer toggle functionality."""

    def test_header_toggle_enables_edit(self, print_dialog: PrintOptionsDialog) -> None:
        """Header checkbox enables/disables header edit."""
        assert print_dialog.header_edit.isEnabled()

        print_dialog.show_header_check.setChecked(False)
        assert not print_dialog.header_edit.isEnabled()

        print_dialog.show_header_check.setChecked(True)
        assert print_dialog.header_edit.isEnabled()

    def test_footer_toggle_enables_edit(self, print_dialog: PrintOptionsDialog) -> None:
        """Footer checkbox enables/disables footer edit."""
        assert print_dialog.footer_edit.isEnabled()

        print_dialog.show_footer_check.setChecked(False)
        assert not print_dialog.footer_edit.isEnabled()

        print_dialog.show_footer_check.setChecked(True)
        assert print_dialog.footer_edit.isEnabled()


class TestPrintDataRetrieval:
    """Test print data retrieval logic."""

    def test_get_print_data_without_viewer(self, print_dialog: PrintOptionsDialog) -> None:
        """Getting print data without viewer returns None."""
        data, offset = print_dialog.get_print_data()
        assert data is None
        assert offset == 0

    def test_get_print_data_all_pages(
        self, print_dialog_with_viewer: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Getting all pages returns full file data."""
        hex_viewer = cast(FakeHexViewer, print_dialog_with_viewer.hex_viewer)
        hex_viewer.file_handler.set_data(test_data)
        print_dialog_with_viewer.all_pages_check.setChecked(True)

        data, offset = print_dialog_with_viewer.get_print_data()

        assert data == test_data
        assert offset == 0

    def test_get_print_data_selection(self, qapp: QApplication, test_data: bytes) -> None:
        """Getting selection returns selected data range."""
        fake_viewer = FakeHexViewer(selection_start=100, selection_end=200)
        fake_viewer.file_handler.set_data(test_data)

        dialog = PrintOptionsDialog(hex_viewer=cast(Any, fake_viewer))
        dialog.selection_check.setChecked(True)

        data, offset = dialog.get_print_data()

        assert data == test_data[100:200]
        assert offset == 100


class TestHexLineFormatting:
    """Test hex line formatting logic."""

    def test_format_hex_line_basic(self, print_dialog: PrintOptionsDialog) -> None:
        """Basic hex line formatting works correctly."""
        data = bytes(range(16))
        line = print_dialog.format_hex_line(0x1000, data, 16)

        assert "00001000" in line
        assert "00 01 02 03" in line
        assert "0E 0F" in line

    def test_format_hex_line_without_offset(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex line without offset column."""
        print_dialog.show_offset_check.setChecked(False)
        data = bytes(range(16))
        line = print_dialog.format_hex_line(0x1000, data, 16)

        assert "00001000" not in line
        assert "00 01 02 03" in line

    def test_format_hex_line_without_ascii(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex line without ASCII column."""
        print_dialog.show_ascii_check.setChecked(False)
        data = b"Hello World!"
        line = print_dialog.format_hex_line(0, data, 16)

        assert "48 65 6C 6C 6F" in line
        assert "Hello" not in line

    def test_format_hex_line_with_ascii(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex line with ASCII column shows printable characters."""
        data = b"Hello World!"
        line = print_dialog.format_hex_line(0, data, 16)

        assert "Hello World!" in line

    def test_format_hex_line_partial_row(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex line with partial row pads correctly."""
        data = bytes(range(8))
        line = print_dialog.format_hex_line(0, data, 16)

        assert "00 01 02 03" in line
        assert "04 05 06 07" in line

    def test_format_hex_line_non_printable_ascii(self, print_dialog: PrintOptionsDialog) -> None:
        """Non-printable characters show as dots in ASCII."""
        data = bytes([0x00, 0x01, 0x41, 0x42, 0xFF])
        line = print_dialog.format_hex_line(0, data, 16)

        assert "..AB." in line


class TestVariableReplacement:
    """Test header/footer variable replacement."""

    def test_replace_page_variables(self, print_dialog: PrintOptionsDialog) -> None:
        """Page variables are replaced correctly."""
        text = "Page %page% of %total%"
        result = print_dialog.replace_variables(text, 3, 10)

        assert "Page 3 of 10" in result

    def test_replace_filename_variable_without_viewer(
        self, print_dialog: PrintOptionsDialog
    ) -> None:
        """Filename variable without viewer shows Untitled."""
        text = "File: %filename%"
        result = print_dialog.replace_variables(text, 1, 1)

        assert "Untitled" in result

    def test_replace_filename_variable_with_viewer(
        self, print_dialog_with_viewer: PrintOptionsDialog
    ) -> None:
        """Filename variable with viewer shows filename."""
        text = "File: %filename%"
        result = print_dialog_with_viewer.replace_variables(text, 1, 1)

        assert "test.bin" in result

    def test_replace_date_variable(self, print_dialog: PrintOptionsDialog) -> None:
        """Date variable is replaced with current date."""
        text = "Printed: %date%"
        result = print_dialog.replace_variables(text, 1, 1)

        assert "Printed:" in result
        assert "-" in result

    def test_replace_multiple_variables(self, print_dialog: PrintOptionsDialog) -> None:
        """Multiple variables replaced in single text."""
        text = "%filename% - Page %page%/%total% - %date%"
        result = print_dialog.replace_variables(text, 2, 5)

        assert "Page 2/5" in result


class TestPageCalculation:
    """Test page count calculation."""

    def test_calculate_total_pages_empty_data(self, print_dialog: PrintOptionsDialog) -> None:
        """Empty data returns 0 pages."""
        total_pages = print_dialog.calculate_total_pages(b"")
        assert total_pages == 0

    def test_calculate_total_pages_small_data(
        self, print_dialog: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Small data returns at least 1 page."""
        total_pages = print_dialog.calculate_total_pages(test_data[:100])
        assert total_pages >= 1

    def test_calculate_total_pages_large_data(
        self, print_dialog: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Large data returns multiple pages."""
        large_data = test_data * 100
        total_pages = print_dialog.calculate_total_pages(large_data)
        assert total_pages > 1

    def test_calculate_total_pages_respects_bytes_per_row(
        self, print_dialog: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Changing bytes per row affects page count."""
        print_dialog.bytes_per_row_spin.setValue(8)
        pages_8bpr = print_dialog.calculate_total_pages(test_data)

        print_dialog.bytes_per_row_spin.setValue(32)
        pages_32bpr = print_dialog.calculate_total_pages(test_data)

        assert pages_8bpr > pages_32bpr

    def test_calculate_total_pages_respects_font_size(
        self, print_dialog: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Changing font size affects page count."""
        print_dialog.font_size_spin.setValue(8)
        pages_small = print_dialog.calculate_total_pages(test_data)

        print_dialog.font_size_spin.setValue(14)
        pages_large = print_dialog.calculate_total_pages(test_data)

        assert pages_small < pages_large


class TestRenderPage:
    """Test page rendering functionality."""

    def test_render_page_basic(
        self, print_dialog_with_viewer: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Basic page rendering completes without errors."""
        fake_painter = FakePainter()
        page_rect = QRectF(0, 0, 600, 800)

        print_dialog_with_viewer.render_page(cast(Any, fake_painter), page_rect, test_data, 0, 1, 1)

        assert fake_painter.font_set_count > 0
        assert fake_painter.draw_text_count > 0

    def test_render_page_with_header(
        self, print_dialog_with_viewer: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Page renders with header."""
        fake_painter = FakePainter()
        print_dialog_with_viewer.show_header_check.setChecked(True)
        page_rect = QRectF(0, 0, 600, 800)

        print_dialog_with_viewer.render_page(cast(Any, fake_painter), page_rect, test_data, 0, 1, 1)

        assert fake_painter.draw_text_count > 0

    def test_render_page_without_header(
        self, print_dialog_with_viewer: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Page renders without header when disabled."""
        fake_painter = FakePainter()
        print_dialog_with_viewer.show_header_check.setChecked(False)
        page_rect = QRectF(0, 0, 600, 800)

        print_dialog_with_viewer.render_page(cast(Any, fake_painter), page_rect, test_data, 0, 1, 1)

        assert fake_painter.draw_text_count > 0

    def test_render_page_with_footer(
        self, print_dialog_with_viewer: PrintOptionsDialog, test_data: bytes
    ) -> None:
        """Page renders with footer."""
        fake_painter = FakePainter()
        print_dialog_with_viewer.show_footer_check.setChecked(True)
        page_rect = QRectF(0, 0, 600, 800)

        print_dialog_with_viewer.render_page(cast(Any, fake_painter), page_rect, test_data, 0, 1, 1)

        assert fake_painter.draw_text_count > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_page_range_validation(self, print_dialog: PrintOptionsDialog) -> None:
        """Page range spin boxes have valid minimum values."""
        assert print_dialog.from_page_spin.minimum() == 1
        assert print_dialog.to_page_spin.minimum() == 1

    def test_bytes_per_row_range(self, print_dialog: PrintOptionsDialog) -> None:
        """Bytes per row has valid range."""
        assert print_dialog.bytes_per_row_spin.minimum() == 8
        assert print_dialog.bytes_per_row_spin.maximum() == 32

    def test_font_size_range(self, print_dialog: PrintOptionsDialog) -> None:
        """Font size has valid range."""
        assert print_dialog.font_size_spin.minimum() == 6
        assert print_dialog.font_size_spin.maximum() == 20

    def test_empty_data_handling(self, print_dialog: PrintOptionsDialog) -> None:
        """Empty data handled gracefully in formatting."""
        line = print_dialog.format_hex_line(0, b"", 16)
        assert isinstance(line, str)

    def test_single_byte_formatting(self, print_dialog: PrintOptionsDialog) -> None:
        """Single byte formats correctly."""
        line = print_dialog.format_hex_line(0, b"\x42", 16)
        assert "42" in line

    def test_maximum_bytes_per_row(self, print_dialog: PrintOptionsDialog) -> None:
        """Maximum bytes per row formats correctly."""
        data = bytes(range(32))
        line = print_dialog.format_hex_line(0, data, 32)
        assert "00 01 02" in line
        assert "1E 1F" in line


class TestPrintOutputFormatValidation:
    """Test print output format validation."""

    def test_hex_output_uppercase(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex output uses uppercase."""
        data = bytes([0xAB, 0xCD, 0xEF])
        line = print_dialog.format_hex_line(0, data, 16)

        assert "AB" in line
        assert "CD" in line
        assert "EF" in line

    def test_offset_formatting_padding(self, print_dialog: PrintOptionsDialog) -> None:
        """Offset is padded to 8 hex digits."""
        data = bytes([0x00])
        line = print_dialog.format_hex_line(0x42, data, 16)

        assert "00000042" in line

    def test_hex_byte_spacing(self, print_dialog: PrintOptionsDialog) -> None:
        """Hex bytes are properly spaced."""
        data = bytes([0x12, 0x34, 0x56, 0x78])
        line = print_dialog.format_hex_line(0, data, 16)

        assert "12 34 56 78" in line

    def test_double_spacing_every_8_bytes(self, print_dialog: PrintOptionsDialog) -> None:
        """Double spacing after 8th byte."""
        data = bytes(range(16))
        line = print_dialog.format_hex_line(0, data, 16)

        hex_portion = line.split("  ")[1] if "00000000" in line else line
        assert "  " in hex_portion


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_print_configuration_workflow(
        self, print_dialog_with_viewer: PrintOptionsDialog
    ) -> None:
        """Complete print configuration workflow."""
        print_dialog_with_viewer.bytes_per_row_spin.setValue(8)
        print_dialog_with_viewer.font_size_spin.setValue(12)
        print_dialog_with_viewer.show_offset_check.setChecked(True)
        print_dialog_with_viewer.show_ascii_check.setChecked(True)
        print_dialog_with_viewer.show_header_check.setChecked(True)
        print_dialog_with_viewer.show_footer_check.setChecked(True)

        data, offset = print_dialog_with_viewer.get_print_data()
        assert data is not None

        total_pages = print_dialog_with_viewer.calculate_total_pages(data)
        assert total_pages >= 1

        line = print_dialog_with_viewer.format_hex_line(0, data[:8], 8)
        assert isinstance(line, str)
        assert len(line) > 0
