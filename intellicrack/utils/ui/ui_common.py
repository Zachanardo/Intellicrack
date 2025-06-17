"""
Common UI utility functions and patterns for Intellicrack.

This module consolidates repeated UI patterns to avoid code duplication.
"""

import os
import webbrowser
from typing import Any, Callable, List, Optional, Tuple

try:
    from PyQt5.QtWidgets import (
        QApplication,
        QFileDialog,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
    )
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False
    QMessageBox = None
    QFileDialog = None
    QApplication = None
    QGroupBox = None
    QHBoxLayout = None
    QLineEdit = None
    QPushButton = None
    QLabel = None


def ask_open_report(parent: Any, report_path: str) -> bool:
    """
    Ask user if they want to open a generated report.
    
    Args:
        parent: Parent widget
        report_path: Path to the report file
        
    Returns:
        True if report was opened
    """
    if not HAS_PYQT:
        return False

    try:
        open_report = QMessageBox.question(
            parent,
            "Open Report",
            "Do you want to open the report?",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes

        if open_report:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
            return True
    except Exception as e:
        # Log the error for debugging UI or file opening issues
        print(f"Error opening report dialog or file: {e}")
        return False

    return False


def get_save_filename(parent: Any, caption: str = "Save File",
                     filter_str: str = "HTML Files (*.html);;All Files (*.*)",
                     default_suffix: str = ".html") -> Optional[str]:
    """
    Show file save dialog and get filename.
    
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
        filename, _ = QFileDialog.getSaveFileName(
            parent, caption, "", filter_str
        )

        if filename and default_suffix:
            if not filename.endswith(default_suffix):
                filename += default_suffix

        return filename
    except Exception as e:
        # Log the error for debugging Qt dialog issues
        print(f"Error opening save file dialog: {e}")
        return None


def create_binary_selection_header(parent_layout: Any,
                                 binary_path: str = "",
                                 show_label: bool = True,
                                 extra_buttons: Optional[List[Tuple[str, Callable]]] = None) -> dict:
    """
    Create a standard binary selection header widget.
    
    Args:
        parent_layout: Layout to add the header to
        binary_path: Initial binary path
        show_label: Whether to show "Binary Path:" label
        extra_buttons: List of (button_text, callback) tuples for additional buttons
        
    Returns:
        Dictionary with widget references: {
            'group': QGroupBox,
            'path_edit': QLineEdit,
            'browse_btn': QPushButton,
            'extra_buttons': {button_text: QPushButton}
        }
    """
    if not HAS_PYQT:
        return {}

    widgets = {'extra_buttons': {}}

    header_group = QGroupBox("Target Binary")
    header_layout = QHBoxLayout(header_group)
    widgets['group'] = header_group

    if show_label:
        header_layout.addWidget(QLabel("Binary Path:"))

    path_edit = QLineEdit(binary_path)
    path_edit.setPlaceholderText("Select target binary file...")
    widgets['path_edit'] = path_edit

    browse_btn = QPushButton("Browse")
    widgets['browse_btn'] = browse_btn

    header_layout.addWidget(path_edit)
    header_layout.addWidget(browse_btn)

    # Add any extra buttons
    if extra_buttons:
        from .ui.ui_button_common import add_extra_buttons
        buttons = add_extra_buttons(header_layout, extra_buttons, widgets)
        widgets['extra_buttons'].update(buttons)

    parent_layout.addWidget(header_group)
    return widgets
