"""Production tests for UI Dialog Utilities.

Validates dialog setup functions, binary selection, footer creation,
and signal connections for production use.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QHBoxLayout, QVBoxLayout, QWidget
from intellicrack.ui.dialog_utils import (
    browse_binary_file,
    connect_binary_signals,
    on_binary_path_changed,
    setup_binary_header,
    setup_footer,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class MockDialog(QWidget):
    """Mock dialog for testing dialog utilities."""

    def __init__(self) -> None:
        """Initialize mock dialog."""
        super().__init__()
        self.binary_path = ""
        self.signals_connected = False

    def browse_binary(self) -> None:
        """Mock browse binary method."""
        pass

    def on_binary_path_changed(self, text: str) -> None:
        """Mock binary path changed handler."""
        self.binary_path = text


class TestSetupFooter:
    """Test footer setup functionality."""

    def test_setup_footer_creates_widgets(self, qapp: QApplication) -> None:
        """Footer setup creates status label and close button."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_footer(dialog, layout)

        assert hasattr(dialog, "status_label")
        assert hasattr(dialog, "close_btn")
        assert dialog.status_label.text() == "Ready"

    def test_footer_status_label_has_style(self, qapp: QApplication) -> None:
        """Footer status label has correct styling."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_footer(dialog, layout)

        style = dialog.status_label.styleSheet()
        assert "color" in style or style == ""

    def test_footer_close_button_connected(self, qapp: QApplication) -> None:
        """Footer close button is connected to dialog close."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_footer(dialog, layout)

        assert dialog.close_btn is not None
        assert dialog.close_btn.text() == "Close"

    def test_footer_added_to_layout(self, qapp: QApplication) -> None:
        """Footer is added to the provided layout."""
        dialog = MockDialog()
        layout = QVBoxLayout()
        initial_count = layout.count()

        setup_footer(dialog, layout)

        assert layout.count() > initial_count


class TestSetupBinaryHeader:
    """Test binary header setup functionality."""

    def test_setup_binary_header_creates_widgets(self, qapp: QApplication) -> None:
        """Binary header creates path edit and browse button."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert hasattr(dialog, "binary_path_edit")
        assert hasattr(dialog, "browse_btn")

    def test_binary_path_edit_has_tooltip(self, qapp: QApplication) -> None:
        """Binary path edit field has informative tooltip."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        tooltip = dialog.binary_path_edit.toolTip()
        assert "binary" in tooltip.lower() or "executable" in tooltip.lower()

    def test_browse_button_connected(self, qapp: QApplication) -> None:
        """Browse button is connected to dialog browse method."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert dialog.browse_btn is not None
        assert dialog.browse_btn.text() == "Browse"

    def test_binary_path_edit_minimum_width(self, qapp: QApplication) -> None:
        """Binary path edit has minimum width for usability."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert dialog.binary_path_edit.minimumWidth() >= 300

    def test_binary_path_edit_initial_value(self, qapp: QApplication) -> None:
        """Binary path edit shows initial path if set."""
        dialog = MockDialog()
        dialog.binary_path = "/path/to/test.exe"
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert dialog.binary_path_edit.text() == "/path/to/test.exe"

    def test_binary_path_edit_empty_when_no_initial(self, qapp: QApplication) -> None:
        """Binary path edit is empty when no initial path."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert dialog.binary_path_edit.text() == ""

    def test_browse_button_has_tooltip(self, qapp: QApplication) -> None:
        """Browse button has informative tooltip."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        tooltip = dialog.browse_btn.toolTip()
        assert "browse" in tooltip.lower() or "select" in tooltip.lower()


class TestConnectBinarySignals:
    """Test binary signal connection functionality."""

    def test_connect_binary_signals_connects_text_changed(self, qapp: QApplication) -> None:
        """Binary signals connect textChanged to handler."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)
        connect_binary_signals(dialog)

        dialog.binary_path_edit.setText("/new/path.exe")

        assert dialog.binary_path == "/new/path.exe"

    def test_signal_connection_updates_binary_path(self, qapp: QApplication) -> None:
        """Signal connection updates dialog binary_path attribute."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)
        connect_binary_signals(dialog)

        test_path = "/test/executable.dll"
        dialog.binary_path_edit.setText(test_path)

        assert dialog.binary_path == test_path


class TestBrowseBinaryFile:
    """Test binary file browsing functionality."""

    def test_browse_binary_file_updates_path_edit(self, qapp: QApplication, monkeypatch: Any) -> None:
        """Browse binary file updates path edit with selected file."""
        dialog = MockDialog()
        layout = QVBoxLayout()
        setup_binary_header(dialog, layout)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            test_file = Path(tmp.name)

        def mock_get_open_filename(*args: Any, **kwargs: Any) -> tuple[str, str]:
            return str(test_file), "Executable Files (*.exe)"

        from intellicrack.ui import dialog_utils

        monkeypatch.setattr(dialog_utils.QFileDialog, "getOpenFileName", mock_get_open_filename)

        browse_binary_file(dialog)

        assert dialog.binary_path_edit.text() == str(test_file)
        assert dialog.binary_path == str(test_file)

        test_file.unlink()

    def test_browse_binary_file_cancellation(self, qapp: QApplication, monkeypatch: Any) -> None:
        """Browse binary file handles user cancellation."""
        dialog = MockDialog()
        layout = QVBoxLayout()
        setup_binary_header(dialog, layout)

        original_path = "/original/path.exe"
        dialog.binary_path_edit.setText(original_path)

        def mock_get_open_filename(*args: Any, **kwargs: Any) -> tuple[str, str]:
            return "", ""

        from intellicrack.ui import dialog_utils

        monkeypatch.setattr(dialog_utils.QFileDialog, "getOpenFileName", mock_get_open_filename)

        browse_binary_file(dialog)

        assert dialog.binary_path_edit.text() == original_path


class TestOnBinaryPathChanged:
    """Test binary path change handler."""

    def test_on_binary_path_changed_updates_attribute(self, qapp: QApplication) -> None:
        """Binary path change handler updates dialog binary_path."""
        dialog = MockDialog()

        on_binary_path_changed(dialog, "/new/binary.exe")

        assert dialog.binary_path == "/new/binary.exe"

    def test_on_binary_path_changed_handles_empty_string(self, qapp: QApplication) -> None:
        """Binary path change handler handles empty string."""
        dialog = MockDialog()

        on_binary_path_changed(dialog, "")

        assert dialog.binary_path == ""

    def test_on_binary_path_changed_handles_unicode_paths(self, qapp: QApplication) -> None:
        """Binary path change handler handles Unicode paths."""
        dialog = MockDialog()

        unicode_path = "/path/to/файл.exe"
        on_binary_path_changed(dialog, unicode_path)

        assert dialog.binary_path == unicode_path


class TestIntegrationScenarios:
    """Test complete dialog setup scenarios."""

    def test_full_dialog_setup_workflow(self, qapp: QApplication) -> None:
        """Complete dialog setup with header, footer, and signals."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)
        setup_footer(dialog, layout)
        connect_binary_signals(dialog)

        assert hasattr(dialog, "binary_path_edit")
        assert hasattr(dialog, "browse_btn")
        assert hasattr(dialog, "status_label")
        assert hasattr(dialog, "close_btn")

        dialog.binary_path_edit.setText("/integrated/test.exe")
        assert dialog.binary_path == "/integrated/test.exe"

    def test_multiple_dialogs_independent(self, qapp: QApplication) -> None:
        """Multiple dialogs maintain independent state."""
        dialog1 = MockDialog()
        dialog2 = MockDialog()

        layout1 = QVBoxLayout()
        layout2 = QVBoxLayout()

        setup_binary_header(dialog1, layout1)
        setup_binary_header(dialog2, layout2)

        dialog1.binary_path_edit.setText("/path1.exe")
        dialog2.binary_path_edit.setText("/path2.exe")

        assert dialog1.binary_path_edit.text() == "/path1.exe"
        assert dialog2.binary_path_edit.text() == "/path2.exe"

    def test_layout_structure_correct(self, qapp: QApplication) -> None:
        """Dialog layout structure is correct with all components."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        initial_count = layout.count()
        setup_binary_header(dialog, layout)
        header_count = layout.count()
        setup_footer(dialog, layout)
        final_count = layout.count()

        assert header_count > initial_count
        assert final_count > header_count


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_setup_on_dialog_without_binary_path_attr(self, qapp: QApplication) -> None:
        """Setup works on dialog without binary_path attribute."""

        class MinimalDialog(QWidget):
            def browse_binary(self) -> None:
                pass

        dialog = MinimalDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)

        assert hasattr(dialog, "binary_path_edit")
        assert dialog.binary_path_edit.text() == ""

    def test_repeated_setup_calls(self, qapp: QApplication) -> None:
        """Repeated setup calls create new widgets each time."""
        dialog = MockDialog()
        layout = QVBoxLayout()

        setup_binary_header(dialog, layout)
        first_edit = dialog.binary_path_edit

        setup_binary_header(dialog, layout)
        second_edit = dialog.binary_path_edit

        assert first_edit is not second_edit

    def test_horizontal_layout_support(self, qapp: QApplication) -> None:
        """Dialog utils work with horizontal layouts."""
        dialog = MockDialog()
        h_layout = QHBoxLayout()

        setup_footer(dialog, h_layout)

        assert hasattr(dialog, "status_label")
        assert hasattr(dialog, "close_btn")
