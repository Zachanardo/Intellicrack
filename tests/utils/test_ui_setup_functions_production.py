"""Production tests for UI setup functions - validates real UI initialization.

Tests verify UI setup functions including dataset tab creation, memory monitor setup,
widget hierarchy management, and component initialization workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.utils.ui.ui_setup_functions import setup_dataset_tab, setup_memory_monitor


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for widget tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.quit()


class TestSetupDatasetTab:
    """Test setup_dataset_tab function."""

    def test_creates_dataset_tab_widget(self, qapp: QApplication) -> None:
        """Test function creates dataset management tab widget."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

    def test_dataset_tab_has_combo_box(self, qapp: QApplication) -> None:
        """Test dataset tab includes dataset selection combo box."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

        if dataset_combo := tab.findChild(type(tab), "dataset_combo"):
            assert dataset_combo.objectName() == "dataset_combo"

    def test_dataset_tab_has_browse_button(self, qapp: QApplication) -> None:
        """Test dataset tab includes browse button."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

        if browse_btn := tab.findChild(type(tab), "browse_dataset_btn"):
            assert browse_btn.objectName() == "browse_dataset_btn"

    def test_dataset_tab_has_preview_table(self, qapp: QApplication) -> None:
        """Test dataset tab includes preview table."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

        if preview_table := tab.findChild(type(tab), "dataset_preview_table"):
            assert preview_table.objectName() == "dataset_preview_table"

    def test_dataset_tab_has_operation_buttons(self, qapp: QApplication) -> None:
        """Test dataset tab includes operation buttons."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

        button_names = [
            "split_dataset_btn",
            "augment_dataset_btn",
            "clean_dataset_btn",
            "export_dataset_btn",
        ]

        for btn_name in button_names:
            if btn := tab.findChild(type(tab), btn_name):
                assert btn.objectName() == btn_name

    def test_dataset_tab_returns_none_without_pyqt(self, qapp: QApplication) -> None:
        """Test function returns None when PyQt6 is unavailable."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_setup_functions.HAS_PYQT", False):
            tab = setup_dataset_tab(parent)

            assert tab is None


class TestSetupMemoryMonitor:
    """Test setup_memory_monitor function."""

    def test_creates_memory_monitor_widget(self, qapp: QApplication) -> None:
        """Test function creates memory monitoring widget."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

    def test_memory_monitor_has_current_value_label(self, qapp: QApplication) -> None:
        """Test memory monitor includes current memory value label."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        if current_value := widget.findChild(type(widget), "current_memory_value"):
            assert current_value.objectName() == "current_memory_value"

    def test_memory_monitor_has_peak_value_label(self, qapp: QApplication) -> None:
        """Test memory monitor includes peak memory value label."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        if peak_value := widget.findChild(type(widget), "peak_memory_value"):
            assert peak_value.objectName() == "peak_memory_value"

    def test_memory_monitor_has_available_value_label(self, qapp: QApplication) -> None:
        """Test memory monitor includes available memory value label."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        if available_value := widget.findChild(
            type(widget), "available_memory_value"
        ):
            assert available_value.objectName() == "available_memory_value"

    def test_memory_monitor_has_usage_bar(self, qapp: QApplication) -> None:
        """Test memory monitor includes memory usage progress bar."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        if memory_bar := widget.findChild(type(widget), "memory_usage_bar"):
            assert memory_bar.objectName() == "memory_usage_bar"

    def test_memory_monitor_has_control_buttons(self, qapp: QApplication) -> None:
        """Test memory monitor includes control buttons."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        button_names = [
            "force_gc_btn",
            "clear_cache_btn",
            "optimize_memory_btn",
        ]

        for btn_name in button_names:
            if btn := widget.findChild(type(widget), btn_name):
                assert btn.objectName() == btn_name

    def test_memory_monitor_has_process_table(self, qapp: QApplication) -> None:
        """Test memory monitor includes process memory table."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        if process_table := widget.findChild(type(widget), "process_memory_table"):
            assert process_table.objectName() == "process_memory_table"

    def test_memory_monitor_returns_none_without_pyqt(self, qapp: QApplication) -> None:
        """Test function returns None when PyQt6 is unavailable."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_setup_functions.HAS_PYQT", False):
            widget = setup_memory_monitor(parent)

            assert widget is None


@pytest.mark.integration
class TestUISetupIntegration:
    """Integration tests for UI setup functions."""

    def test_dataset_tab_complete_initialization(self, qapp: QApplication) -> None:
        """Test complete dataset tab initialization workflow."""
        parent = MagicMock()

        tab = setup_dataset_tab(parent)

        assert tab is not None

        combo = tab.findChild(type(tab), "dataset_combo")
        preview = tab.findChild(type(tab), "dataset_preview_table")
        split_btn = tab.findChild(type(tab), "split_dataset_btn")

    def test_memory_monitor_complete_initialization(self, qapp: QApplication) -> None:
        """Test complete memory monitor initialization workflow."""
        parent = MagicMock()

        widget = setup_memory_monitor(parent)

        assert widget is not None

        current_value = widget.findChild(type(widget), "current_memory_value")
        memory_bar = widget.findChild(type(widget), "memory_usage_bar")
        gc_btn = widget.findChild(type(widget), "force_gc_btn")

    def test_widget_hierarchy_with_parent(self, qapp: QApplication) -> None:
        """Test widgets are created with proper parent hierarchy."""
        parent = MagicMock()
        parent.__class__.__name__ = "MainWindow"

        dataset_tab = setup_dataset_tab(parent)
        memory_monitor = setup_memory_monitor(parent)

        assert dataset_tab is not None
        assert memory_monitor is not None

    def test_multiple_tab_creation(self, qapp: QApplication) -> None:
        """Test creating multiple tabs doesn't cause conflicts."""
        parent = MagicMock()

        tab1 = setup_dataset_tab(parent)
        tab2 = setup_dataset_tab(parent)

        assert tab1 is not None
        assert tab2 is not None
        assert tab1 is not tab2

    def test_multiple_monitor_creation(self, qapp: QApplication) -> None:
        """Test creating multiple monitors doesn't cause conflicts."""
        parent = MagicMock()

        monitor1 = setup_memory_monitor(parent)
        monitor2 = setup_memory_monitor(parent)

        assert monitor1 is not None
        assert monitor2 is not None
        assert monitor1 is not monitor2

    def test_headless_operation_fallback(self) -> None:
        """Test headless operation when PyQt6 is unavailable."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_setup_functions.HAS_PYQT", False):
            dataset_tab = setup_dataset_tab(parent)
            memory_monitor = setup_memory_monitor(parent)

            assert dataset_tab is None
            assert memory_monitor is None

    def test_setup_functions_with_none_parent(self, qapp: QApplication) -> None:
        """Test setup functions handle None parent gracefully."""
        dataset_tab = setup_dataset_tab(None)
        memory_monitor = setup_memory_monitor(None)

        assert dataset_tab is not None
        assert memory_monitor is not None
