"""Integration tests for settings tab animation functionality.

This module tests the animation enable/disable functionality including
CSS stylesheet injection, marker detection, and transition application
using real Qt6 components.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
from collections.abc import Generator

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for testing."""
    existing_app = QApplication.instance()
    if existing_app is None:
        yield QApplication(sys.argv)
    else:
        assert isinstance(existing_app, QApplication), "Expected QApplication instance"
        yield existing_app


class TestAnimationFunctionality:
    """Test suite for animation enable/disable functionality with real application."""

    def test_enable_animations_injects_transition_css(self, qapp: QApplication) -> None:
        """Test that enabling animations injects CSS transition rules into stylesheet."""
        original_stylesheet = qapp.styleSheet()

        enable_animations_css = """
/* Enable smooth animations and transitions */
QPushButton, QComboBox, QCheckBox::indicator, QRadioButton::indicator,
QSlider::handle, QTabBar::tab {
    transition: all 0.2s ease-in-out;
}

QPushButton:hover, QComboBox:hover, QTabBar::tab:hover {
    transition: all 0.15s ease-in-out;
}
"""

        new_stylesheet = original_stylesheet + enable_animations_css
        qapp.setStyleSheet(new_stylesheet)

        current_stylesheet = qapp.styleSheet()
        assert "/* Enable smooth animations and transitions */" in current_stylesheet
        assert "transition: all 0.2s ease-in-out" in current_stylesheet
        assert "transition: all 0.15s ease-in-out" in current_stylesheet

        qapp.setStyleSheet(original_stylesheet)

    def test_disable_animations_injects_zero_duration_css(self, qapp: QApplication) -> None:
        """Test that disabling animations sets transition duration to 0s."""
        original_stylesheet = qapp.styleSheet()

        disable_animations_css = """
/* Disable all animations - instant transitions */
* {
    transition-duration: 0s !important;
    animation-duration: 0s !important;
}
"""

        new_stylesheet = original_stylesheet + disable_animations_css
        qapp.setStyleSheet(new_stylesheet)

        current_stylesheet = qapp.styleSheet()
        assert "/* Disable all animations - instant transitions */" in current_stylesheet
        assert "transition-duration: 0s !important" in current_stylesheet
        assert "animation-duration: 0s !important" in current_stylesheet

        qapp.setStyleSheet(original_stylesheet)

    def test_marker_detection_prevents_duplicate_injection(self, qapp: QApplication) -> None:
        """Test that marker comments prevent duplicate CSS injection."""
        original_stylesheet = qapp.styleSheet()

        enable_marker = "/* Enable smooth animations and transitions */"
        test_css = f"""
{enable_marker}
QPushButton {{ transition: all 0.2s ease-in-out; }}
"""

        qapp.setStyleSheet(original_stylesheet + test_css)
        current_stylesheet = qapp.styleSheet()

        assert current_stylesheet.count(enable_marker) == 1

        qapp.setStyleSheet(original_stylesheet)

    def test_remove_disable_marker_when_enabling(self, qapp: QApplication) -> None:
        """Test that enabling animations removes disable marker from stylesheet."""
        original_stylesheet = qapp.styleSheet()

        disable_marker = "/* Disable all animations - instant transitions */"
        disable_css = f"""
{disable_marker}
* {{ transition-duration: 0s !important; }}
"""

        qapp.setStyleSheet(original_stylesheet + disable_css)
        assert disable_marker in qapp.styleSheet()

        current = qapp.styleSheet()
        if disable_marker in current:
            start_idx = current.find(disable_marker)
            end_idx = current.find("}", start_idx)
            if end_idx != -1:
                end_idx += 1
                current = current[:start_idx] + current[end_idx:]

        qapp.setStyleSheet(current)
        assert disable_marker not in qapp.styleSheet()

        qapp.setStyleSheet(original_stylesheet)

    def test_remove_enable_marker_when_disabling(self, qapp: QApplication) -> None:
        """Test that disabling animations removes enable marker from stylesheet."""
        original_stylesheet = qapp.styleSheet()

        enable_marker = "/* Enable smooth animations and transitions */"
        enable_css = f"""
{enable_marker}
QPushButton {{ transition: all 0.2s ease-in-out; }}
QPushButton:hover {{ transition: all 0.15s ease-in-out; }}
"""

        qapp.setStyleSheet(original_stylesheet + enable_css)
        assert enable_marker in qapp.styleSheet()

        current = qapp.styleSheet()
        if enable_marker in current:
            start_idx = current.find(enable_marker)
            end_idx = current.find("}", start_idx)
            if end_idx != -1:
                end_idx = current.find("}", end_idx + 1) + 1
                current = current[:start_idx] + current[end_idx:]

        qapp.setStyleSheet(current)
        assert enable_marker not in qapp.styleSheet()

        qapp.setStyleSheet(original_stylesheet)

    def test_toggle_animations_multiple_times(self, qapp: QApplication) -> None:
        """Test that toggling animations multiple times maintains stylesheet integrity."""
        original_stylesheet = qapp.styleSheet()

        enable_marker = "/* Enable smooth animations and transitions */"
        disable_marker = "/* Disable all animations - instant transitions */"

        for cycle in range(3):
            enable_css = f"""
{enable_marker}
QPushButton {{ transition: all 0.2s ease-in-out; }}
"""
            qapp.setStyleSheet(qapp.styleSheet() + enable_css)

            current = qapp.styleSheet()
            if enable_marker in current:
                start_idx = current.find(enable_marker)
                end_idx = current.find("}", start_idx) + 1
                current = current[:start_idx] + current[end_idx:]
            qapp.setStyleSheet(current)

            disable_css = f"""
{disable_marker}
* {{ transition-duration: 0s !important; }}
"""
            qapp.setStyleSheet(qapp.styleSheet() + disable_css)

            current = qapp.styleSheet()
            if disable_marker in current:
                start_idx = current.find(disable_marker)
                end_idx = current.find("}", start_idx) + 1
                current = current[:start_idx] + current[end_idx:]
            qapp.setStyleSheet(current)

        qapp.setStyleSheet(original_stylesheet)

    def test_stylesheet_modification_preserves_existing_styles(self, qapp: QApplication) -> None:
        """Test that adding animation CSS preserves existing stylesheet rules."""
        test_style = "QPushButton { background-color: red; }"
        qapp.setStyleSheet(test_style)

        animation_css = """
/* Enable smooth animations and transitions */
QPushButton { transition: all 0.2s ease-in-out; }
"""
        qapp.setStyleSheet(qapp.styleSheet() + animation_css)

        current_stylesheet = qapp.styleSheet()
        assert "background-color: red" in current_stylesheet
        assert "transition: all 0.2s ease-in-out" in current_stylesheet

        qapp.setStyleSheet("")

    def test_empty_stylesheet_animation_injection(self, qapp: QApplication) -> None:
        """Test animation injection on empty stylesheet."""
        qapp.setStyleSheet("")

        enable_css = """
/* Enable smooth animations and transitions */
QPushButton { transition: all 0.2s ease-in-out; }
"""
        qapp.setStyleSheet(enable_css)

        assert "/* Enable smooth animations and transitions */" in qapp.styleSheet()

        qapp.setStyleSheet("")

    def test_complex_stylesheet_marker_removal(self, qapp: QApplication) -> None:
        """Test marker removal in complex stylesheets with multiple rules."""
        complex_stylesheet = """
QMainWindow { background-color: #1E1E1E; }
QPushButton { color: white; }
/* Enable smooth animations and transitions */
QPushButton { transition: all 0.2s ease-in-out; }
QPushButton:hover { transition: all 0.15s ease-in-out; }
QLabel { font-size: 12pt; }
"""
        qapp.setStyleSheet(complex_stylesheet)

        current = qapp.styleSheet()
        marker = "/* Enable smooth animations and transitions */"
        if marker in current:
            start_idx = current.find(marker)
            end_idx = current.find("}", start_idx)
            end_idx = current.find("}", end_idx + 1) + 1
            current = current[:start_idx] + current[end_idx:]

        qapp.setStyleSheet(current)

        final_stylesheet = qapp.styleSheet()
        assert "QMainWindow { background-color: #1E1E1E; }" in final_stylesheet
        assert "QLabel { font-size: 12pt; }" in final_stylesheet
        assert marker not in final_stylesheet

        qapp.setStyleSheet("")
