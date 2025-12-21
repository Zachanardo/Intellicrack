"""Provide UI utility functions and patterns for Intellicrack.

This module consolidates repeated UI patterns to avoid code duplication.

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

import os
import webbrowser
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QFileDialog, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QWidget

try:
    from PyQt6.QtWidgets import QFileDialog, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QWidget

    HAS_PYQT = True
except ImportError as e:
    logger.error("Import error in ui_common: %s", e)
    HAS_PYQT = False


def ask_open_report(parent: QWidget | None, report_path: str) -> bool:
    """Ask user if they want to open a generated report.

    Args:
        parent: Parent widget
        report_path: Path to the report file

    Returns:
        True if report was opened

    """
    if not HAS_PYQT:
        return False

    try:
        from PyQt6.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            parent,
            "Open Report",
            "Do you want to open the report?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        open_report = reply == QMessageBox.StandardButton.Yes

        if open_report:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
            return True
    except Exception as e:
        logger.error("Exception in ui_common: %s", e)
        print(f"Error opening report dialog or file: {e}")
        return False

    return False


def get_save_filename(
    parent: QWidget | None,
    caption: str = "Save File",
    filter_str: str = "HTML Files (*.html);;All Files (*.*)",
    default_suffix: str = ".html",
) -> str | None:
    """Show file save dialog and get filename.

    Args:
        parent: Parent widget
        caption: Dialog caption
        filter_str: File filter string
        default_suffix: Default file suffix to add if missing

    Returns:
        Selected filename or None

    """
    if not HAS_PYQT:
        return None

    try:
        from PyQt6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(
            parent,
            caption,
            "",
            filter_str,
        )

        if filename and default_suffix and not filename.endswith(default_suffix):
            filename += default_suffix

        return filename if filename else None
    except Exception as e:
        logger.error("Exception in ui_common: %s", e)
        print(f"Error opening save file dialog: {e}")
        return None


def create_binary_selection_header(
    parent_layout: QHBoxLayout | Any,
    binary_path: str = "",
    show_label: bool = True,
    extra_buttons: list[tuple[str, Callable[..., Any]]] | None = None,
) -> dict[str, Any]:
    """Create a standard binary selection header widget.

    Args:
        parent_layout: Layout to add the header to
        binary_path: Initial binary path
        show_label: Whether to show "Binary Path:" label
        extra_buttons: List of (button_text, callback) tuples for additional buttons

    Returns:
        dict: Dictionary with widget references containing:
            - 'group': QGroupBox
            - 'path_edit': QLineEdit
            - 'browse_btn': QPushButton
            - 'extra_buttons': dict mapping button_text to QPushButton

    """
    if not HAS_PYQT:
        return {}

    from PyQt6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton

    header_group = QGroupBox("Target Binary")
    header_layout = QHBoxLayout(header_group)
    widgets: dict[str, Any] = {"extra_buttons": {}, "group": header_group}
    if show_label:
        header_layout.addWidget(QLabel("Binary Path:"))

    path_edit = QLineEdit(binary_path)
    if not binary_path:
        path_edit.setText("(No binary selected)")
    widgets["path_edit"] = path_edit

    browse_btn = QPushButton("Browse")
    widgets["browse_btn"] = browse_btn

    header_layout.addWidget(path_edit)
    header_layout.addWidget(browse_btn)

    if extra_buttons:
        from .ui_button_common import add_extra_buttons

        buttons = add_extra_buttons(header_layout, extra_buttons, widgets)
        extra_buttons_dict = cast(dict[str, Any], widgets["extra_buttons"])
        extra_buttons_dict.update(buttons)

    if hasattr(parent_layout, 'addWidget'):
        parent_layout.addWidget(header_group)
    return widgets
