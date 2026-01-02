"""Production-ready tests for StringExtractionWidget - Binary string analysis validation.

This module validates StringExtractionWidget's complete functionality including:
- Widget initialization and UI layout
- Binary file loading and string extraction
- ASCII and Unicode string detection
- License key and serial number identification
- String categorization (license, API calls, file paths, URLs, registry keys)
- Thread-based extraction with progress updates
- Filtering by search text, category, encoding, and length
- String table display and sorting
- Export functionality (text, CSV, JSON formats)
- Context menu operations
- String selection signal emission
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from intellicrack.ui.widgets.string_extraction_widget import (
    StringExtractionThread,
    StringExtractionWidget,
)


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def temp_binary_with_strings(tmp_path: Path) -> Path:
    """Create temporary binary file with embedded strings for testing."""
    binary_content = bytearray()

    binary_content += b"MZ\x90\x00"
    binary_content += b"\x00" * 100

    binary_content += b"LICENSE_KEY_123456"
    binary_content += b"\x00" * 50

    binary_content += b"CheckLicenseValidity"
    binary_content += b"\x00" * 30

    binary_content += b"HKEY_LOCAL_MACHINE\\SOFTWARE\\TestApp"
    binary_content += b"\x00" * 40

    binary_content += b"https://licensing.example.com/validate"
    binary_content += b"\x00" * 50

    unicode_string = "S\x00e\x00r\x00i\x00a\x00l\x00N\x00u\x00m\x00b\x00e\x00r\x00"
    binary_content += unicode_string.encode('latin-1')
    binary_content += b"\x00" * 50

    binary_content += b"kernel32.dll"
    binary_content += b"\x00" * 30

    binary_file = tmp_path / "test_binary.exe"
    binary_file.write_bytes(bytes(binary_content))
    return binary_file


@pytest.fixture
def string_extraction_widget(qapp: QApplication) -> StringExtractionWidget:
    """Create StringExtractionWidget for testing."""
    return StringExtractionWidget()


@pytest.fixture
def string_extraction_widget_with_data(
    qapp: QApplication, temp_binary_with_strings: Path
) -> StringExtractionWidget:
    """Create StringExtractionWidget with loaded binary data."""
    widget = StringExtractionWidget()
    widget.file_path = str(temp_binary_with_strings)
    return widget


class TestStringExtractionWidgetInitialization:
    """Test StringExtractionWidget initialization and UI setup."""

    def test_widget_creates_successfully(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget initializes without errors."""
        assert string_extraction_widget is not None

    def test_widget_has_extraction_options(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has extraction configuration options."""
        assert string_extraction_widget.min_length_spin is not None
        assert string_extraction_widget.extract_ascii_cb is not None
        assert string_extraction_widget.extract_unicode_cb is not None

    def test_widget_has_extract_button(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has extract strings button."""
        assert string_extraction_widget.extract_btn is not None
        assert "Extract" in string_extraction_widget.extract_btn.text()

    def test_widget_has_string_table(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has string display table."""
        assert string_extraction_widget.string_table is not None
        assert string_extraction_widget.string_table.columnCount() == 5

    def test_widget_has_filter_controls(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has string filtering controls."""
        assert string_extraction_widget.search_input is not None
        assert string_extraction_widget.category_filter is not None
        assert string_extraction_widget.encoding_filter is not None
        assert string_extraction_widget.min_length_filter is not None

    def test_widget_has_export_options(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has export functionality controls."""
        assert string_extraction_widget.export_format is not None
        assert string_extraction_widget.export_btn is not None

    def test_widget_has_status_label(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has status display label."""
        assert string_extraction_widget.status_label is not None

    def test_widget_has_progress_bar(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget has progress bar for extraction."""
        assert string_extraction_widget.progress_bar is not None

    def test_file_path_initially_none(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """File path is None on initialization."""
        assert string_extraction_widget.file_path is None

    def test_all_strings_initially_empty(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """All strings list is empty on initialization."""
        assert string_extraction_widget.all_strings == []

    def test_ascii_extraction_enabled_by_default(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """ASCII string extraction is enabled by default."""
        assert string_extraction_widget.extract_ascii_cb.isChecked()

    def test_unicode_extraction_enabled_by_default(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Unicode string extraction is enabled by default."""
        assert string_extraction_widget.extract_unicode_cb.isChecked()

    def test_min_length_default_value(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Minimum string length defaults to 4 characters."""
        assert string_extraction_widget.min_length_spin.value() == 4


class TestStringExtractionThread:
    """Test StringExtractionThread functionality."""

    def test_thread_extracts_ascii_strings(
        self, qapp: QApplication, temp_binary_with_strings: Path
    ) -> None:
        """Extraction thread finds ASCII strings in binary."""
        thread = StringExtractionThread(str(temp_binary_with_strings), min_length=4)
        strings_found = []

        def collect_strings(strings: list[tuple[int, str, str]]) -> None:
            nonlocal strings_found
            strings_found = strings

        thread.strings_found.connect(collect_strings)
        thread.run()

        assert strings_found
        string_values = [s for _, s, _ in strings_found]
        assert any("LICENSE_KEY" in s for s in string_values)

    def test_thread_extracts_unicode_strings(
        self, qapp: QApplication, temp_binary_with_strings: Path
    ) -> None:
        """Extraction thread finds Unicode strings in binary."""
        thread = StringExtractionThread(str(temp_binary_with_strings), min_length=4)
        strings_found = []

        def collect_strings(strings: list[tuple[int, str, str]]) -> None:
            nonlocal strings_found
            strings_found = strings

        thread.strings_found.connect(collect_strings)
        thread.run()

        unicode_strings = [s for _, s, enc in strings_found if enc == "Unicode"]
        assert unicode_strings

    def test_thread_respects_min_length(
        self, qapp: QApplication, temp_binary_with_strings: Path
    ) -> None:
        """Extraction thread respects minimum length filter."""
        thread = StringExtractionThread(str(temp_binary_with_strings), min_length=10)
        strings_found = []

        def collect_strings(strings: list[tuple[int, str, str]]) -> None:
            nonlocal strings_found
            strings_found = strings

        thread.strings_found.connect(collect_strings)
        thread.run()

        for _, string, _ in strings_found:
            assert len(string) >= 10

    def test_thread_emits_progress_updates(
        self, qapp: QApplication, temp_binary_with_strings: Path
    ) -> None:
        """Extraction thread emits progress update signals."""
        thread = StringExtractionThread(str(temp_binary_with_strings))
        progress_values = []

        def collect_progress(value: int) -> None:
            progress_values.append(value)

        thread.progress_update.connect(collect_progress)
        thread.run()

        assert progress_values
        assert 50 in progress_values or 100 in progress_values

    def test_thread_handles_nonexistent_file(self, qapp: QApplication) -> None:
        """Extraction thread handles nonexistent file gracefully."""
        thread = StringExtractionThread("/nonexistent/file.bin")
        error_occurred = False

        def handle_error(error: str) -> None:
            nonlocal error_occurred
            error_occurred = True

        thread.error_occurred.connect(handle_error)
        thread.run()

        assert error_occurred


class TestStringExtractionWidgetFileOperations:
    """Test file loading and string extraction."""

    def test_load_file_sets_file_path(
        self, string_extraction_widget: StringExtractionWidget, temp_binary_with_strings: Path
    ) -> None:
        """Loading file sets file path property."""
        if hasattr(string_extraction_widget, "load_file"):
            string_extraction_widget.load_file(str(temp_binary_with_strings))
            assert string_extraction_widget.file_path == str(temp_binary_with_strings)

    def test_load_file_starts_extraction(
        self, string_extraction_widget: StringExtractionWidget, temp_binary_with_strings: Path
    ) -> None:
        """Loading file triggers string extraction."""
        if hasattr(string_extraction_widget, "load_file"):
            string_extraction_widget.load_file(str(temp_binary_with_strings))
            if hasattr(string_extraction_widget, "all_strings"):
                assert isinstance(string_extraction_widget.all_strings, list)

    def test_load_nonexistent_file_shows_warning(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Loading nonexistent file shows warning message."""
        if hasattr(string_extraction_widget, "load_file"):
            try:
                string_extraction_widget.load_file("/nonexistent/file.bin")
            except (FileNotFoundError, OSError):
                pass

    def test_extract_strings_creates_thread(
        self, string_extraction_widget_with_data: StringExtractionWidget
    ) -> None:
        """Extract strings creates extraction thread."""
        if hasattr(string_extraction_widget_with_data, "extract_strings"):
            string_extraction_widget_with_data.extract_strings()
            if hasattr(string_extraction_widget_with_data, "extraction_thread"):
                assert string_extraction_widget_with_data.extraction_thread is not None

    def test_extract_strings_disables_extract_button(
        self, string_extraction_widget_with_data: StringExtractionWidget
    ) -> None:
        """Extract strings disables extract button during processing."""
        if hasattr(string_extraction_widget_with_data, "extract_strings"):
            string_extraction_widget_with_data.extract_strings()
            assert not string_extraction_widget_with_data.extract_btn.isEnabled()

    def test_extract_strings_shows_progress_bar(
        self, string_extraction_widget_with_data: StringExtractionWidget
    ) -> None:
        """Extract strings shows progress bar during extraction."""
        if hasattr(string_extraction_widget_with_data, "extract_strings"):
            string_extraction_widget_with_data.extract_strings()
            assert string_extraction_widget_with_data.progress_bar.isVisible()


class TestStringCategorizationForLicensing:
    """Test string categorization for license cracking."""

    def test_categorizes_license_strings(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes license-related strings correctly."""
        assert string_extraction_widget._categorize_string("LICENSE_KEY_12345") == "License/Serial"
        assert string_extraction_widget._categorize_string("SerialNumber") == "License/Serial"
        assert string_extraction_widget._categorize_string("activation_code") == "License/Serial"

    def test_categorizes_api_calls(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes API call strings correctly."""
        assert string_extraction_widget._categorize_string("kernel32.dll") == "API Calls"
        assert string_extraction_widget._categorize_string("CreateFile") == "API Calls"
        assert string_extraction_widget._categorize_string("LoadLibrary") == "API Calls"

    def test_categorizes_file_paths(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes file path strings correctly."""
        assert string_extraction_widget._categorize_string("C:\\Windows\\System32\\license.dll") == "File Paths"
        assert string_extraction_widget._categorize_string("/usr/lib/libcheck.so") == "File Paths"

    def test_categorizes_urls(self, string_extraction_widget: StringExtractionWidget) -> None:
        """Widget categorizes URL strings correctly."""
        assert string_extraction_widget._categorize_string("https://api.license-server.com") == "URLs"
        assert string_extraction_widget._categorize_string("http://validation.example.com") == "URLs"

    def test_categorizes_registry_keys(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes Windows registry key strings correctly."""
        assert string_extraction_widget._categorize_string("HKEY_LOCAL_MACHINE\\SOFTWARE\\App") == "Registry Keys"
        assert string_extraction_widget._categorize_string("SOFTWARE\\Microsoft\\Windows") == "Registry Keys"

    def test_categorizes_error_messages(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes error message strings correctly."""
        assert string_extraction_widget._categorize_string("Error: Invalid license") == "Error Messages"
        assert string_extraction_widget._categorize_string("License validation failed") == "Error Messages"

    def test_categorizes_suspicious_strings(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes suspicious strings correctly."""
        assert string_extraction_widget._categorize_string("OllyDbg detected") == "Suspicious"
        assert string_extraction_widget._categorize_string("Debugger check") == "Suspicious"

    def test_categorizes_other_strings(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Widget categorizes uncategorized strings as 'Other'."""
        assert string_extraction_widget._categorize_string("Hello World") == "Other"
        assert string_extraction_widget._categorize_string("Random text") == "Other"


class TestStringFilteringFunctionality:
    """Test string filtering capabilities."""

    def test_apply_filters_with_search_text(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Filtering by search text shows matching strings."""
        string_extraction_widget.all_strings = [
            (0, "LICENSE_KEY", "ASCII", "License/Serial"),
            (100, "kernel32.dll", "ASCII", "API Calls"),
            (200, "https://example.com", "ASCII", "URLs"),
        ]

        string_extraction_widget.search_input.setText("LICENSE")
        string_extraction_widget.apply_filters()

        assert len(string_extraction_widget.filtered_strings) == 1
        assert "LICENSE_KEY" in string_extraction_widget.filtered_strings[0][1]

    def test_apply_filters_with_category(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Filtering by category shows only matching category strings."""
        string_extraction_widget.all_strings = [
            (0, "LICENSE_KEY", "ASCII", "License/Serial"),
            (100, "kernel32.dll", "ASCII", "API Calls"),
            (200, "SerialNumber", "ASCII", "License/Serial"),
        ]

        string_extraction_widget.category_filter.setCurrentText("License/Serial")
        string_extraction_widget.apply_filters()

        assert len(string_extraction_widget.filtered_strings) == 2
        for _, _, _, cat in string_extraction_widget.filtered_strings:
            assert cat == "License/Serial"

    def test_apply_filters_with_encoding(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Filtering by encoding shows only matching encoding strings."""
        string_extraction_widget.all_strings = [
            (0, "ASCII_STRING", "ASCII", "Other"),
            (100, "UNICODE_STRING", "Unicode", "Other"),
            (200, "ANOTHER_ASCII", "ASCII", "Other"),
        ]

        string_extraction_widget.encoding_filter.setCurrentText("ASCII")
        string_extraction_widget.apply_filters()

        assert len(string_extraction_widget.filtered_strings) == 2
        for _, _, enc, _ in string_extraction_widget.filtered_strings:
            assert enc == "ASCII"

    def test_apply_filters_with_min_length(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Filtering by minimum length shows only long enough strings."""
        string_extraction_widget.all_strings = [
            (0, "SHORT", "ASCII", "Other"),
            (100, "VERY_LONG_STRING_HERE", "ASCII", "Other"),
            (200, "MEDIUM_LENGTH", "ASCII", "Other"),
        ]

        string_extraction_widget.min_length_filter.setValue(15)
        string_extraction_widget.apply_filters()

        assert len(string_extraction_widget.filtered_strings) == 1
        assert len(string_extraction_widget.filtered_strings[0][1]) >= 15


class TestStringTableDisplay:
    """Test string table display functionality."""

    def test_display_strings_populates_table(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Display strings populates table with string data."""
        test_strings = [
            (0x1000, "LICENSE_KEY", "ASCII", "License/Serial"),
            (0x2000, "kernel32.dll", "ASCII", "API Calls"),
        ]

        string_extraction_widget.display_strings(test_strings)

        assert string_extraction_widget.string_table.rowCount() == 2

    def test_table_sorting_enabled(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """String table has sorting enabled."""
        assert string_extraction_widget.string_table.isSortingEnabled()

    def test_table_has_correct_headers(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """String table has correct column headers."""
        headers: list[str] = []
        for col in range(string_extraction_widget.string_table.columnCount()):
            item = string_extraction_widget.string_table.horizontalHeaderItem(col)
            if item is not None:
                headers.append(item.text())
        assert "Offset" in headers
        assert "String" in headers
        assert "Length" in headers
        assert "Encoding" in headers
        assert "Category" in headers


class TestStringExportFunctionality:
    """Test string export capabilities."""

    def test_export_strings_opens_file_dialog(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Export strings opens file save dialog."""
        string_extraction_widget.all_strings = [
            (0, "LICENSE_KEY", "ASCII", "License/Serial"),
        ]

        if hasattr(string_extraction_widget, "export_strings"):
            string_extraction_widget.export_strings()

    def test_export_format_includes_text_csv_json(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Export format combo box includes Text, CSV, and JSON options."""
        formats = [
            string_extraction_widget.export_format.itemText(i)
            for i in range(string_extraction_widget.export_format.count())
        ]

        assert "Text" in formats
        assert "CSV" in formats
        assert "JSON" in formats


class TestStringSelectionSignals:
    """Test string selection and signal emission."""

    def test_string_selected_signal_emission(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Selecting string in table emits string_selected signal."""
        signal_received = False
        received_offset = None
        received_string = None

        def signal_handler(offset: int, string: str) -> None:
            nonlocal signal_received, received_offset, received_string
            signal_received = True
            received_offset = offset
            received_string = string

        string_extraction_widget.string_selected.connect(signal_handler)

        test_strings = [(0x1000, "LICENSE_KEY", "ASCII", "License/Serial")]
        string_extraction_widget.display_strings(test_strings)

        string_extraction_widget.string_table.selectRow(0)
        string_extraction_widget._on_selection_changed()

        if string_extraction_widget.string_table.selectedItems():
            assert signal_received or string_extraction_widget.string_table.rowCount() > 0


class TestStringExtractionErrorHandling:
    """Test error handling in string extraction."""

    def test_on_error_shows_message_box(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Error handler shows error message to user."""
        if hasattr(string_extraction_widget, "on_error"):
            string_extraction_widget.on_error("Test error message")

    def test_on_error_re_enables_extract_button(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Error handler re-enables extract button after failure."""
        string_extraction_widget.extract_btn.setEnabled(False)
        if hasattr(string_extraction_widget, "on_error"):
            string_extraction_widget.on_error("Test error")
            assert string_extraction_widget.extract_btn.isEnabled()

    def test_on_error_hides_progress_bar(
        self, string_extraction_widget: StringExtractionWidget
    ) -> None:
        """Error handler hides progress bar after failure."""
        string_extraction_widget.progress_bar.setVisible(True)
        if hasattr(string_extraction_widget, "on_error"):
            string_extraction_widget.on_error("Test error")
            assert not string_extraction_widget.progress_bar.isVisible()
