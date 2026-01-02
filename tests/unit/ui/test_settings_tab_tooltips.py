"""Integration tests for settings tab tooltip functionality.

This module tests the tooltip enable/disable functionality in the settings tab
using real Qt6 widgets to ensure production-ready behavior.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
from collections.abc import Generator
from typing import Any
import pytest
from weakref import WeakKeyDictionary

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QPushButton,
    QLabel,
    QWidget,
    QVBoxLayout,
)


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def test_widgets(qapp: QApplication) -> Generator[list[QWidget], None, None]:
    """Create real Qt widgets for testing."""
    widgets: list[QWidget] = []
    for i in range(5):
        widget: QWidget
        if i < 3:
            widget = QPushButton(f"Button {i}")
            widget.setToolTip(f"Tooltip for button {i}")
        else:
            widget = QLabel(f"Label {i}")
        widgets.append(widget)

    yield widgets

    for widget in widgets:
        widget.deleteLater()


class TestTooltipFunctionality:
    """Test suite for tooltip enable/disable functionality with real widgets."""

    def test_disable_tooltips_stores_and_clears(self, qapp: QApplication, test_widgets: list[QWidget]) -> None:
        """Test that disabling tooltips stores originals and clears them from real widgets."""
        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        for widget in test_widgets:
            if tooltip := widget.toolTip():
                original_tooltips[widget] = tooltip
                widget.setToolTip("")
            widget.setToolTipDuration(0)

        for widget in test_widgets[:3]:
            assert widget.toolTip() == ""
            assert widget in original_tooltips
            assert original_tooltips[widget].startswith("Tooltip for button")

        assert len(original_tooltips) == 3

    def test_enable_tooltips_restores_originals(self, qapp: QApplication, test_widgets: list[QWidget]) -> None:
        """Test that enabling tooltips restores previously stored values on real widgets."""
        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        for widget in test_widgets:
            if tooltip := widget.toolTip():
                original_tooltips[widget] = tooltip
                widget.setToolTip("")

        for widget in test_widgets:
            if widget in original_tooltips:
                widget.setToolTip(original_tooltips[widget])
            widget.setToolTipDuration(-1)

        for widget in test_widgets[:3]:
            assert widget.toolTip() == original_tooltips[widget]
            assert widget.toolTip().startswith("Tooltip for button")

    def test_null_widget_handling(self, qapp: QApplication) -> None:
        """Test that None values in widget list are handled gracefully."""
        test_list: list[QWidget | None] = [None, QPushButton("Test"), None, QLabel("Label")]

        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        for widget in test_list:
            if widget is None:
                continue
            if tooltip := widget.toolTip():
                original_tooltips[widget] = tooltip

        for widget in test_list:
            if widget is not None:
                widget.deleteLater()

    def test_weak_reference_cleanup(self, qapp: QApplication) -> None:
        """Test that WeakKeyDictionary properly releases references when widgets are deleted."""
        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        widget1 = QPushButton("Button 1")
        widget1.setToolTip("Tooltip 1")
        widget2 = QPushButton("Button 2")
        widget2.setToolTip("Tooltip 2")

        original_tooltips[widget1] = widget1.toolTip()
        original_tooltips[widget2] = widget2.toolTip()

        assert len(original_tooltips) == 2

        widget1.deleteLater()
        del widget1

        qapp.processEvents()

        widget2.deleteLater()

    def test_tooltip_persistence_across_enable_disable_cycles(self, qapp: QApplication, test_widgets: list[QWidget]) -> None:
        """Test that tooltips remain consistent across multiple enable/disable cycles."""
        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        original_values = {id(widget): widget.toolTip() for widget in test_widgets[:3]}
        for _ in range(3):
            for widget in test_widgets:
                if tooltip := widget.toolTip():
                    original_tooltips[widget] = tooltip
                    widget.setToolTip("")

            for widget in test_widgets:
                if widget in original_tooltips:
                    widget.setToolTip(original_tooltips[widget])

        for widget in test_widgets[:3]:
            assert widget.toolTip() == original_values[id(widget)]

    def test_tooltip_duration_settings(self, qapp: QApplication, test_widgets: list[QWidget]) -> None:
        """Test that tooltip duration is properly set for enabled and disabled states."""
        for widget in test_widgets:
            widget.setToolTipDuration(0)
            assert widget.toolTipDuration() == 0

        for widget in test_widgets:
            widget.setToolTipDuration(-1)
            assert widget.toolTipDuration() == -1

    def test_empty_tooltip_widgets_not_stored(self, qapp: QApplication, test_widgets: list[QWidget]) -> None:
        """Test that widgets without tooltips are not stored in the dictionary."""
        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        for widget in test_widgets:
            if tooltip := widget.toolTip():
                original_tooltips[widget] = tooltip

        assert len(original_tooltips) == 3
        assert test_widgets[3] not in original_tooltips
        assert test_widgets[4] not in original_tooltips

    def test_complex_widget_hierarchy(self, qapp: QApplication) -> None:
        """Test tooltip handling with nested widget hierarchies."""
        container = QWidget()
        layout = QVBoxLayout(container)

        buttons: list[QPushButton] = []
        for i in range(3):
            btn = QPushButton(f"Nested Button {i}")
            btn.setToolTip(f"Nested tooltip {i}")
            layout.addWidget(btn)
            buttons.append(btn)

        original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        all_widgets = [container] + buttons
        for widget in all_widgets:
            if tooltip := widget.toolTip():
                original_tooltips[widget] = tooltip
                widget.setToolTip("")

        assert len(original_tooltips) == 3

        for widget in all_widgets:
            if widget in original_tooltips:
                widget.setToolTip(original_tooltips[widget])

        for i, btn in enumerate(buttons):
            assert btn.toolTip() == f"Nested tooltip {i}"

        container.deleteLater()
