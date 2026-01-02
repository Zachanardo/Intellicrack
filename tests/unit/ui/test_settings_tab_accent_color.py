"""Integration tests for settings tab accent color functionality.

This module tests the accent color replacement functionality including
regex-based replacement, case-insensitive matching, and multiple format handling
using real Qt6 application stylesheets.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import re
import sys
from collections.abc import Generator

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


class TestAccentColorFunctionality:
    """Test suite for accent color replacement with real application stylesheets."""

    def test_replace_default_accent_color_uppercase(self, qapp: QApplication) -> None:
        """Test replacement of default accent color in uppercase format."""
        test_stylesheet = """
QPushButton {
    background-color: #0078D4;
    border: 1px solid #0078D4;
}
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#FF5733"
        default_colors = ["#0078D4", "#0078d4"]

        current_stylesheet = qapp.styleSheet()
        for default_color in default_colors:
            pattern = re.compile(re.escape(default_color), re.IGNORECASE)
            current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert new_color in final_stylesheet
        assert "#0078D4" not in final_stylesheet

        qapp.setStyleSheet("")

    def test_replace_default_accent_color_lowercase(self, qapp: QApplication) -> None:
        """Test replacement of default accent color in lowercase format."""
        test_stylesheet = """
QPushButton {
    background-color: #0078d4;
    border-color: #0078d4;
}
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#00FF00"
        default_colors = ["#0078D4", "#0078d4"]

        current_stylesheet = qapp.styleSheet()
        for default_color in default_colors:
            pattern = re.compile(re.escape(default_color), re.IGNORECASE)
            current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert new_color in final_stylesheet
        assert "#0078d4" not in final_stylesheet.lower()

        qapp.setStyleSheet("")

    def test_replace_mixed_case_accent_colors(self, qapp: QApplication) -> None:
        """Test replacement with mixed case color codes in stylesheet."""
        test_stylesheet = """
QPushButton { background-color: #0078D4; }
QLabel { color: #0078d4; }
QComboBox { border: 1px solid #0078D4; }
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#CC00CC"
        default_colors = ["#0078D4", "#0078d4"]

        current_stylesheet = qapp.styleSheet()
        for default_color in default_colors:
            pattern = re.compile(re.escape(default_color), re.IGNORECASE)
            current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert final_stylesheet.count(new_color) >= 3
        assert "#0078D4" not in final_stylesheet
        assert "#0078d4" not in final_stylesheet

        qapp.setStyleSheet("")

    def test_replace_custom_accent_color(self, qapp: QApplication) -> None:
        """Test replacement of previously set custom accent color."""
        test_stylesheet = """
QPushButton { background-color: #FF6B6B; }
QSlider::handle { background-color: #FF6B6B; }
"""
        qapp.setStyleSheet(test_stylesheet)

        old_custom_color = "#FF6B6B"
        new_color = "#4ECDC4"

        current_stylesheet = qapp.styleSheet()
        pattern = re.compile(re.escape(old_custom_color), re.IGNORECASE)
        current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert new_color in final_stylesheet
        assert old_custom_color not in final_stylesheet

        qapp.setStyleSheet("")

    def test_preserve_non_accent_colors(self, qapp: QApplication) -> None:
        """Test that non-accent colors are preserved during replacement."""
        test_stylesheet = """
QMainWindow { background-color: #1E1E1E; }
QPushButton { background-color: #0078D4; color: #FFFFFF; }
QLabel { color: #808080; }
"""
        qapp.setStyleSheet(test_stylesheet)

        new_accent = "#FF0000"
        default_colors = ["#0078D4", "#0078d4"]

        current_stylesheet = qapp.styleSheet()
        for default_color in default_colors:
            pattern = re.compile(re.escape(default_color), re.IGNORECASE)
            current_stylesheet = pattern.sub(new_accent, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert "#1E1E1E" in final_stylesheet
        assert "#FFFFFF" in final_stylesheet
        assert "#808080" in final_stylesheet
        assert new_accent in final_stylesheet

        qapp.setStyleSheet("")

    def test_multiple_accent_color_changes(self, qapp: QApplication) -> None:
        """Test multiple sequential accent color changes."""
        test_stylesheet = """
QPushButton { background-color: #0078D4; }
"""
        qapp.setStyleSheet(test_stylesheet)

        colors = ["#FF5733", "#33FF57", "#3357FF", "#F333FF"]

        for new_color in colors:
            current_stylesheet = qapp.styleSheet()

            default_colors = ["#0078D4", "#0078d4"]
            for default_color in default_colors:
                pattern = re.compile(re.escape(default_color), re.IGNORECASE)
                current_stylesheet = pattern.sub(new_color, current_stylesheet)

            for prev_color in colors[:colors.index(new_color)]:
                pattern = re.compile(re.escape(prev_color), re.IGNORECASE)
                current_stylesheet = pattern.sub(new_color, current_stylesheet)

            qapp.setStyleSheet(current_stylesheet)

            final_stylesheet = qapp.styleSheet()
            assert new_color in final_stylesheet

        qapp.setStyleSheet("")

    def test_case_insensitive_regex_replacement(self, qapp: QApplication) -> None:
        """Test that regex pattern matching is case-insensitive."""
        test_stylesheet = """
QPushButton { background-color: #0078d4; }
QLabel { color: #0078D4; }
QComboBox { border-color: #0078D4; }
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#ABCDEF"
        search_color = "#0078D4"

        current_stylesheet = qapp.styleSheet()
        pattern = re.compile(re.escape(search_color), re.IGNORECASE)
        current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert "#0078d4" not in final_stylesheet.lower()
        assert new_color.lower() in final_stylesheet.lower()

        qapp.setStyleSheet("")

    def test_empty_stylesheet_accent_color_application(self, qapp: QApplication) -> None:
        """Test that accent color replacement works on empty stylesheet."""
        qapp.setStyleSheet("")

        new_stylesheet = """
QPushButton { background-color: #FF0000; }
"""
        qapp.setStyleSheet(new_stylesheet)

        assert "#FF0000" in qapp.styleSheet()

        qapp.setStyleSheet("")

    def test_complex_stylesheet_with_multiple_accent_occurrences(self, qapp: QApplication) -> None:
        """Test replacement in complex stylesheet with many accent color occurrences."""
        test_stylesheet = """
QTabBar::tab:selected { border-top: 2px solid #0078D4; }
QPushButton:hover { background-color: #0078D4; }
QSlider::sub-page:horizontal { background-color: #0078D4; }
QCheckBox::indicator:checked { background-color: #0078D4; }
QProgressBar::chunk { background-color: #0078d4; }
QListWidget::item:selected { background-color: #0078D4; }
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#00AA00"
        default_colors = ["#0078D4", "#0078d4"]

        current_stylesheet = qapp.styleSheet()
        for default_color in default_colors:
            pattern = re.compile(re.escape(default_color), re.IGNORECASE)
            current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert final_stylesheet.count(new_color) >= 6
        assert "#0078D4" not in final_stylesheet
        assert "#0078d4" not in final_stylesheet

        qapp.setStyleSheet("")

    def test_special_characters_in_color_values(self, qapp: QApplication) -> None:
        """Test that regex properly escapes special characters."""
        test_stylesheet = """
QPushButton { background-color: #0078D4; }
"""
        qapp.setStyleSheet(test_stylesheet)

        new_color = "#A1B2C3"
        search_pattern = "#0078D4"

        current_stylesheet = qapp.styleSheet()
        pattern = re.compile(re.escape(search_pattern), re.IGNORECASE)
        current_stylesheet = pattern.sub(new_color, current_stylesheet)

        qapp.setStyleSheet(current_stylesheet)

        final_stylesheet = qapp.styleSheet()
        assert new_color in final_stylesheet
        assert search_pattern not in final_stylesheet

        qapp.setStyleSheet("")
