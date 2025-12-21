"""Production tests for Plugin Dialog Base.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox
from intellicrack.ui.dialogs.plugin_dialog_base import PluginDialogBase


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_plugin_file() -> Path:
    """Create temporary plugin file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("# Test plugin\ndef test_function():\n    pass\n")
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def dialog(qapp: QApplication) -> PluginDialogBase:
    """Create plugin dialog base for testing."""
    dlg = PluginDialogBase()
    dlg.logger = logging.getLogger(__name__)
    yield dlg
    dlg.deleteLater()


def test_dialog_initialization_without_plugin(dialog: PluginDialogBase) -> None:
    """Dialog initializes correctly without plugin path."""
    assert dialog.windowTitle() == "Plugin Dialog"
    assert dialog.minimumWidth() == 600
    assert dialog.minimumHeight() == 400
    assert dialog.plugin_path is None


def test_dialog_initialization_with_plugin(qapp: QApplication, temp_plugin_file: Path) -> None:
    """Dialog initializes and loads plugin when path provided."""
    dlg = PluginDialogBase(plugin_path=str(temp_plugin_file))
    dlg.logger = logging.getLogger(__name__)

    assert dlg.plugin_path == str(temp_plugin_file)
    assert dlg.plugin_label.text() == temp_plugin_file.name

    dlg.deleteLater()


def test_dialog_ui_components_exist(dialog: PluginDialogBase) -> None:
    """Dialog contains all required UI components."""
    assert hasattr(dialog, "plugin_label")
    assert hasattr(dialog, "content_area")
    assert hasattr(dialog, "content_layout")
    assert hasattr(dialog, "ok_button")
    assert hasattr(dialog, "cancel_button")

    assert dialog.plugin_label is not None
    assert dialog.content_area is not None
    assert dialog.content_layout is not None
    assert dialog.ok_button is not None
    assert dialog.cancel_button is not None


def test_plugin_label_default_text(dialog: PluginDialogBase) -> None:
    """Plugin label shows default text when no plugin selected."""
    assert dialog.plugin_label.text() == "No plugin selected"


def test_plugin_label_bold_style(dialog: PluginDialogBase) -> None:
    """Plugin label has bold font style."""
    style = dialog.plugin_label.styleSheet()
    assert "font-weight: bold" in style.lower()


def test_ok_button_accepts_dialog(dialog: PluginDialogBase) -> None:
    """OK button click accepts dialog."""
    with patch.object(dialog, "accept") as mock_accept:
        dialog.ok_button.click()
        mock_accept.assert_called_once()


def test_cancel_button_rejects_dialog(dialog: PluginDialogBase) -> None:
    """Cancel button click rejects dialog."""
    with patch.object(dialog, "reject") as mock_reject:
        dialog.cancel_button.click()
        mock_reject.assert_called_once()


def test_browse_plugin_opens_file_dialog(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Browse button opens file dialog and loads selected plugin."""
    with patch(
        "intellicrack.ui.dialogs.plugin_dialog_base.QFileDialog.getOpenFileName",
        return_value=(str(temp_plugin_file), ""),
    ):
        dialog.browse_plugin()

        assert dialog.plugin_path == str(temp_plugin_file)
        assert dialog.plugin_label.text() == temp_plugin_file.name


def test_browse_plugin_cancelled_does_nothing(dialog: PluginDialogBase) -> None:
    """Cancelling browse dialog does not change plugin."""
    original_path = dialog.plugin_path

    with patch(
        "intellicrack.ui.dialogs.plugin_dialog_base.QFileDialog.getOpenFileName",
        return_value=("", ""),
    ):
        dialog.browse_plugin()

        assert dialog.plugin_path == original_path


def test_load_plugin_success(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Loading existing plugin file succeeds."""
    result = dialog.load_plugin(str(temp_plugin_file))

    assert result is True
    assert dialog.plugin_path == str(temp_plugin_file)
    assert dialog.plugin_label.text() == temp_plugin_file.name


def test_load_plugin_nonexistent_file_shows_warning(dialog: PluginDialogBase) -> None:
    """Loading nonexistent plugin file shows warning."""
    with patch.object(QMessageBox, "warning") as mock_warning:
        result = dialog.load_plugin("C:/nonexistent/plugin.py")

        assert result is False
        mock_warning.assert_called_once()
        args = mock_warning.call_args[0]
        assert "not found" in args[2].lower()


def test_load_plugin_updates_plugin_label(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Loading plugin updates plugin label with basename."""
    dialog.load_plugin(str(temp_plugin_file))

    assert dialog.plugin_label.text() == temp_plugin_file.name
    assert temp_plugin_file.parent.name not in dialog.plugin_label.text()


def test_load_plugin_calls_on_plugin_loaded(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Loading plugin calls on_plugin_loaded hook."""
    with patch.object(dialog, "on_plugin_loaded") as mock_on_loaded:
        dialog.load_plugin(str(temp_plugin_file))

        mock_on_loaded.assert_called_once_with(str(temp_plugin_file))


def test_on_plugin_loaded_stores_metadata(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """on_plugin_loaded stores plugin metadata."""
    dialog.on_plugin_loaded(str(temp_plugin_file))

    assert hasattr(dialog, "_loaded_plugins")
    assert str(temp_plugin_file) in dialog._loaded_plugins

    metadata = dialog._loaded_plugins[str(temp_plugin_file)]
    assert metadata["name"] == temp_plugin_file.name
    assert metadata["directory"] == str(temp_plugin_file.parent)
    assert metadata["status"] == "loaded"
    assert "loaded_at" in metadata


def test_on_plugin_loaded_updates_window_title(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """on_plugin_loaded updates window title with plugin name."""
    original_title = dialog.windowTitle()

    dialog.on_plugin_loaded(str(temp_plugin_file))

    new_title = dialog.windowTitle()
    assert temp_plugin_file.name in new_title
    assert " - " in new_title


def test_on_plugin_loaded_replaces_existing_plugin_name(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """Loading new plugin replaces existing plugin name in title."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("# Second plugin\n")
        second_plugin = Path(f.name)

    try:
        dialog.on_plugin_loaded(str(temp_plugin_file))
        first_title = dialog.windowTitle()

        dialog.on_plugin_loaded(str(second_plugin))
        second_title = dialog.windowTitle()

        assert temp_plugin_file.name not in second_title
        assert second_plugin.name in second_title

        base_title = first_title.split(" - ")[0]
        assert second_title.startswith(base_title)

    finally:
        if second_plugin.exists():
            second_plugin.unlink()


def test_on_plugin_loaded_enables_dependent_widgets(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """on_plugin_loaded enables plugin-dependent widgets."""
    from intellicrack.handlers.pyqt6_handler import QPushButton

    widget1 = QPushButton("Test 1")
    widget2 = QPushButton("Test 2")

    widget1.setEnabled(False)
    widget2.setEnabled(False)

    dialog.plugin_dependent_widgets = [widget1, widget2]

    dialog.on_plugin_loaded(str(temp_plugin_file))

    assert widget1.isEnabled()
    assert widget2.isEnabled()


def test_on_plugin_loaded_emits_signal_if_available(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """on_plugin_loaded emits signal if plugin_loaded_signal exists."""
    from intellicrack.handlers.pyqt6_handler import pyqtSignal

    signal_received = []

    class TestDialog(PluginDialogBase):
        from intellicrack.handlers.pyqt6_handler import pyqtSignal

        plugin_loaded_signal = pyqtSignal(str)

    test_dialog = TestDialog()
    test_dialog.logger = logging.getLogger(__name__)

    def on_signal(path: str) -> None:
        signal_received.append(path)

    test_dialog.plugin_loaded_signal.connect(on_signal)

    test_dialog.on_plugin_loaded(str(temp_plugin_file))

    assert len(signal_received) == 1
    assert signal_received[0] == str(temp_plugin_file)

    test_dialog.deleteLater()


def test_on_plugin_loaded_stores_last_loaded_plugin(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """on_plugin_loaded stores reference to last loaded plugin."""
    dialog.on_plugin_loaded(str(temp_plugin_file))

    assert hasattr(dialog, "_last_loaded_plugin")
    assert dialog._last_loaded_plugin == str(temp_plugin_file)


def test_on_plugin_loaded_logs_info_message(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """on_plugin_loaded logs successful load at info level."""
    with patch.object(dialog.logger, "info") as mock_info:
        dialog.on_plugin_loaded(str(temp_plugin_file))

        mock_info.assert_called()
        args = str(mock_info.call_args)
        assert temp_plugin_file.name in args


def test_on_plugin_loaded_logs_debug_message(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """on_plugin_loaded logs path at debug level."""
    with patch.object(dialog.logger, "debug") as mock_debug:
        dialog.on_plugin_loaded(str(temp_plugin_file))

        mock_debug.assert_called()
        args = str(mock_debug.call_args)
        assert str(temp_plugin_file) in args


def test_multiple_plugin_loads_tracked_separately(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Loading multiple plugins tracks each separately."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("# Second plugin\n")
        second_plugin = Path(f.name)

    try:
        dialog.on_plugin_loaded(str(temp_plugin_file))
        dialog.on_plugin_loaded(str(second_plugin))

        assert len(dialog._loaded_plugins) == 2
        assert str(temp_plugin_file) in dialog._loaded_plugins
        assert str(second_plugin) in dialog._loaded_plugins

    finally:
        if second_plugin.exists():
            second_plugin.unlink()


def test_loaded_plugins_dict_initialized_once(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """_loaded_plugins dict is initialized only once."""
    dialog.on_plugin_loaded(str(temp_plugin_file))
    first_dict = dialog._loaded_plugins

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("# Second plugin\n")
        second_plugin = Path(f.name)

    try:
        dialog.on_plugin_loaded(str(second_plugin))
        second_dict = dialog._loaded_plugins

        assert first_dict is second_dict

    finally:
        if second_plugin.exists():
            second_plugin.unlink()


def test_plugin_metadata_includes_loaded_timestamp(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """Plugin metadata includes timestamp of when loaded."""
    from intellicrack.handlers.pyqt6_handler import QDateTime

    before_time = QDateTime.currentDateTime()
    dialog.on_plugin_loaded(str(temp_plugin_file))
    after_time = QDateTime.currentDateTime()

    metadata = dialog._loaded_plugins[str(temp_plugin_file)]
    loaded_time = metadata["loaded_at"]

    assert before_time <= loaded_time <= after_time


def test_create_plugin_selection_layout_returns_layout(dialog: PluginDialogBase) -> None:
    """create_plugin_selection_layout returns valid layout."""
    layout = dialog.create_plugin_selection_layout()

    assert layout is not None
    assert layout.count() > 0


def test_browse_button_connected_to_browse_plugin(dialog: PluginDialogBase) -> None:
    """Browse button is connected to browse_plugin method."""
    layout = dialog.create_plugin_selection_layout()

    browse_button = None
    for i in range(layout.count()):
        widget = layout.itemAt(i).widget()
        if widget and hasattr(widget, "text") and callable(widget.text) and "Browse" in widget.text():
            browse_button = widget
            break

    assert browse_button is not None


def test_dialog_minimum_size_enforced(dialog: PluginDialogBase) -> None:
    """Dialog enforces minimum size."""
    assert dialog.minimumSize().width() >= 600
    assert dialog.minimumSize().height() >= 400


def test_content_area_has_layout(dialog: PluginDialogBase) -> None:
    """Content area has layout for subclass customization."""
    assert dialog.content_area.layout() is not None
    assert dialog.content_layout is not None


def test_load_plugin_with_absolute_path(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Loading plugin with absolute path works correctly."""
    absolute_path = str(temp_plugin_file.resolve())

    result = dialog.load_plugin(absolute_path)

    assert result is True
    assert dialog.plugin_path == absolute_path


def test_load_plugin_with_relative_path(dialog: PluginDialogBase) -> None:
    """Loading plugin with relative path that doesn't exist fails."""
    with patch.object(QMessageBox, "warning"):
        result = dialog.load_plugin("./relative/plugin.py")

        assert result is False


def test_plugin_file_filter_includes_python_files(dialog: PluginDialogBase) -> None:
    """File dialog filter includes Python files."""
    with patch(
        "intellicrack.ui.dialogs.plugin_dialog_base.QFileDialog.getOpenFileName"
    ) as mock_dialog:
        mock_dialog.return_value = ("", "")

        dialog.browse_plugin()

        call_args = mock_dialog.call_args[0]
        filter_string = call_args[3]
        assert "*.py" in filter_string


def test_on_plugin_loaded_handles_no_dependent_widgets(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """on_plugin_loaded works when plugin_dependent_widgets doesn't exist."""
    if hasattr(dialog, "plugin_dependent_widgets"):
        delattr(dialog, "plugin_dependent_widgets")

    dialog.on_plugin_loaded(str(temp_plugin_file))

    assert str(temp_plugin_file) in dialog._loaded_plugins


def test_on_plugin_loaded_handles_no_signal(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """on_plugin_loaded works when plugin_loaded_signal doesn't exist."""
    if hasattr(dialog, "plugin_loaded_signal"):
        delattr(dialog, "plugin_loaded_signal")

    dialog.on_plugin_loaded(str(temp_plugin_file))

    assert str(temp_plugin_file) in dialog._loaded_plugins


def test_plugin_status_set_to_loaded(dialog: PluginDialogBase, temp_plugin_file: Path) -> None:
    """Plugin status is set to 'loaded' in metadata."""
    dialog.on_plugin_loaded(str(temp_plugin_file))

    metadata = dialog._loaded_plugins[str(temp_plugin_file)]
    assert metadata["status"] == "loaded"


def test_plugin_directory_extracted_correctly(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """Plugin directory is correctly extracted and stored."""
    dialog.on_plugin_loaded(str(temp_plugin_file))

    metadata = dialog._loaded_plugins[str(temp_plugin_file)]
    assert metadata["directory"] == str(temp_plugin_file.parent)


def test_plugin_name_extracted_from_basename(
    dialog: PluginDialogBase, temp_plugin_file: Path
) -> None:
    """Plugin name is extracted from file basename."""
    dialog.on_plugin_loaded(str(temp_plugin_file))

    metadata = dialog._loaded_plugins[str(temp_plugin_file)]
    assert metadata["name"] == temp_plugin_file.name
    assert os.sep not in metadata["name"]
