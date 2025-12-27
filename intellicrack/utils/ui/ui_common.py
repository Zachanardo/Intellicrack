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

from __future__ import annotations

import os
import webbrowser
from collections.abc import Callable
from typing import TYPE_CHECKING

from intellicrack.types.ui import (
    BinarySelectionWidgets,
    LayoutProtocol,
    StandardButton,
    WidgetProtocol,
    get_file_dialog,
    get_message_box,
)
from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    pass

try:
    from PyQt6.QtWidgets import (
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
    )

    HAS_PYQT = True
except ImportError as e:
    logger.error("Import error in ui_common: %s", e)
    HAS_PYQT = False


def ask_open_report(parent: WidgetProtocol | None, report_path: str) -> bool:
    """Ask user if they want to open a generated report.

    Args:
        parent: Parent widget (WidgetProtocol or None)
        report_path: Path to the report file

    Returns:
        True if report was opened

    """
    MessageBox = get_message_box()

    try:
        reply = MessageBox.question(
            parent,
            "Open Report",
            "Do you want to open the report?",
            StandardButton.Yes | StandardButton.No,
        )

        if reply == StandardButton.Yes:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
            return True
    except Exception as e:
        logger.error("Exception in ui_common: %s", e)
        return False

    return False


def get_save_filename(
    parent: WidgetProtocol | None,
    caption: str = "Save File",
    filter_str: str = "HTML Files (*.html);;All Files (*.*)",
    default_suffix: str = ".html",
) -> str | None:
    """Show file save dialog and get filename.

    Args:
        parent: Parent widget (WidgetProtocol or None)
        caption: Dialog caption
        filter_str: File filter string
        default_suffix: Default file suffix to add if missing

    Returns:
        Selected filename or None

    """
    FileDialog = get_file_dialog()

    try:
        filename, _ = FileDialog.getSaveFileName(
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
        return None


def create_binary_selection_header(
    parent_layout: LayoutProtocol,
    binary_path: str = "",
    show_label: bool = True,
    extra_buttons: list[tuple[str, Callable[..., object]]] | None = None,
) -> BinarySelectionWidgets:
    """Create a standard binary selection header widget.

    Args:
        parent_layout: Layout to add the header to (must implement LayoutProtocol)
        binary_path: Initial binary path
        show_label: Whether to show "Binary Path:" label
        extra_buttons: List of (button_text, callback) tuples for additional buttons

    Returns:
        BinarySelectionWidgets: Pydantic model with widget references containing:
            - group: QGroupBox
            - path_edit: QLineEdit
            - browse_btn: QPushButton
            - extra_buttons: dict mapping button_text to QPushButton

    """
    if not HAS_PYQT:
        return BinarySelectionWidgets()

    from PyQt6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton

    header_group = QGroupBox("Target Binary")
    header_layout = QHBoxLayout(header_group)
    extra_buttons_dict: dict[str, object] = {}

    if show_label:
        header_layout.addWidget(QLabel("Binary Path:"))

    path_edit = QLineEdit(binary_path)
    if not binary_path:
        path_edit.setText("(No binary selected)")

    browse_btn = QPushButton("Browse")

    header_layout.addWidget(path_edit)
    header_layout.addWidget(browse_btn)

    if extra_buttons:
        from .ui_button_common import add_extra_buttons

        buttons = add_extra_buttons(header_layout, extra_buttons, extra_buttons_dict)
        extra_buttons_dict.update(buttons)

    if hasattr(parent_layout, "addWidget"):
        parent_layout.addWidget(header_group)

    return BinarySelectionWidgets(
        group=header_group,
        path_edit=path_edit,
        browse_btn=browse_btn,
        extra_buttons=extra_buttons_dict,
    )
