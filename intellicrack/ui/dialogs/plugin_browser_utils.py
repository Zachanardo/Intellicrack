"""Copyright (C) 2025 Zachary Flint.

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.

Plugin Browser Utility Functions.

Shared utilities for plugin browsing functionality to eliminate code duplication.
"""

import os

from intellicrack.handlers.pyqt6_handler import QFileDialog, QWidget


def browse_for_plugin(parent_widget: QWidget | None, title: str = "Select Plugin") -> str:
    """Browse for a plugin file using a file dialog.

    Args:
        parent_widget: Parent widget for the dialog
        title: Dialog title

    Returns:
        Selected file path or empty string if cancelled

    """
    file_path, _ = QFileDialog.getOpenFileName(
        parent_widget,
        title,
        "",
        "Plugin Files (*.py *.js);;All Files (*.*)",
    )

    return file_path


def get_plugin_basename(path: str) -> str:
    """Get the basename of a plugin file.

    Args:
        path: Full path to plugin file

    Returns:
        Basename of the file

    """
    return os.path.basename(path) if path else ""
