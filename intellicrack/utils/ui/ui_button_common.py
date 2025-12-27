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

from __future__ import annotations

from collections.abc import Callable

from intellicrack.utils.logger import logger


try:
    from intellicrack.handlers.pyqt6_handler import QPushButton

    PYQT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in ui_button_common: %s", e)
    PYQT_AVAILABLE = False


def add_extra_buttons(
    header_layout: object,
    extra_buttons: list[tuple[str, Callable[..., object]]],
    widget_refs: dict[str, object] | None = None,
) -> dict[str, object]:
    """Add extra buttons to a header layout with consistent styling.

    This is an internal function that operates on Qt layouts directly.
    The header_layout parameter is typed as object to avoid Protocol
    compatibility issues with Qt's signature, but is expected to be
    a QLayout at runtime.

    Args:
        header_layout: Qt layout to add buttons to (typically QHBoxLayout).
        extra_buttons: List of (button_text, callback) tuples.
        widget_refs: Optional dict to store button references.

    Returns:
        Dictionary mapping button text to button widget objects.

    """
    if not PYQT_AVAILABLE or not extra_buttons:
        return {}

    if not hasattr(header_layout, "addWidget"):
        return {}

    add_widget_method = getattr(header_layout, "addWidget")
    buttons: dict[str, object] = {}

    for button_text, callback in extra_buttons:
        btn = QPushButton(button_text)
        btn.clicked.connect(callback)

        if button_text == "Analyze Binary":
            btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")

        add_widget_method(btn)
        buttons[button_text] = btn

        if widget_refs is not None:
            if button_text == "Analyze Binary":
                widget_refs["analyze_btn"] = btn
            elif "extra_buttons" in widget_refs:
                extra_buttons_dict = widget_refs["extra_buttons"]
                if isinstance(extra_buttons_dict, dict):
                    extra_buttons_dict[button_text] = btn

    return buttons


def get_button_style(button_text: str) -> str:
    """Get the appropriate style for a button based on its text.

    Args:
        button_text: Text of the button.

    Returns:
        Style sheet string for the button.

    """
    if button_text == "Analyze Binary":
        return "QPushButton { background-color: #2196F3; color: white; font-weight: bold; }"
    return ""
