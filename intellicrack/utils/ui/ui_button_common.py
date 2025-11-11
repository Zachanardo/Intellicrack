"""Provide UI button utilities and shared button functionality.

Common UI button utilities to avoid code duplication.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from intellicrack.utils.logger import logger

try:
    from intellicrack.handlers.pyqt6_handler import QPushButton

    PYQT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in ui_button_common: %s", e)
    PYQT_AVAILABLE = False


def add_extra_buttons(header_layout, extra_buttons, widget_refs=None):
    """Add extra buttons to a header layout with consistent styling.

    Args:
        header_layout: Qt layout to add buttons to
        extra_buttons: List of (button_text, callback) tuples
        widget_refs: Optional dict to store button references

    Returns:
        dict: Dictionary of button text -> button widget

    """
    if not PYQT_AVAILABLE or not extra_buttons:
        return {}

    buttons = {}

    for button_text, callback in extra_buttons:
        btn = QPushButton(button_text)
        btn.clicked.connect(callback)

        # Apply special styling for Analyze Binary button
        if button_text == "Analyze Binary":
            btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")

        header_layout.addWidget(btn)
        buttons[button_text] = btn

        # Store reference if widget_refs provided
        if widget_refs is not None:
            if button_text == "Analyze Binary":
                widget_refs["analyze_btn"] = btn
            elif "extra_buttons" in widget_refs:
                widget_refs["extra_buttons"][button_text] = btn

    return buttons


def get_button_style(button_text) -> str:
    """Get the appropriate style for a button based on its text.

    Args:
        button_text: Text of the button

    Returns:
        str: Style sheet string

    """
    if button_text == "Analyze Binary":
        return "QPushButton { background-color: #2196F3; color: white; font-weight: bold; }"
    return ""
