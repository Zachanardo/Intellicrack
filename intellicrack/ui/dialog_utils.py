"""Provide dialog utilities and methods.

Copyright (C) 2025 Zachary Flint

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
"""

from .handlers.pyqt6_handler import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
)


def setup_footer(dialog, layout):
    """Set up standard dialog footer with status and close button."""
    footer_layout = QHBoxLayout()

    dialog.status_label = QLabel("Ready")
    dialog.status_label.setStyleSheet("QLabel { color: #666; }")

    dialog.close_btn = QPushButton("Close")
    dialog.close_btn.clicked.connect(dialog.close)

    footer_layout.addWidget(dialog.status_label)
    footer_layout.addStretch()
    footer_layout.addWidget(dialog.close_btn)

    layout.addLayout(footer_layout)


def setup_binary_header(dialog, layout):
    """Set up header with binary selection."""
    header_group = QGroupBox("Target Binary")
    header_layout = QHBoxLayout(header_group)

    # Set up binary path input field with initial value
    current_path = getattr(dialog, "binary_path", "")
    dialog.binary_path_edit = QLineEdit(current_path if current_path else "")

    # Set tooltip to guide users on expected file types
    dialog.binary_path_edit.setToolTip(
        "Enter or browse for executable binary path\n"
        "Supported formats: PE (*.exe, *.dll), ELF (*.so), Mach-O (*.dylib)"
    )

    # Configure text field appearance and behavior
    dialog.binary_path_edit.setMinimumWidth(300)
    if not current_path:
        dialog.binary_path_edit.setStyleSheet("QLineEdit { color: #888; }")

    dialog.browse_btn = QPushButton("Browse")
    dialog.browse_btn.clicked.connect(dialog.browse_binary)
    dialog.browse_btn.setToolTip("Open file browser to select target binary")

    header_layout.addWidget(dialog.binary_path_edit)
    header_layout.addWidget(dialog.browse_btn)

    layout.addWidget(header_group)


def connect_binary_signals(dialog):
    """Connect common binary-related signals."""
    dialog.binary_path_edit.textChanged.connect(dialog.on_binary_path_changed)


def browse_binary_file(dialog):
    """Browse for binary file using standard file dialog."""
    file_path, _ = QFileDialog.getOpenFileName(
        dialog,
        "Select Target Binary",
        "",
        "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
    )
    if file_path:
        dialog.binary_path_edit.setText(file_path)
        dialog.binary_path = file_path


def on_binary_path_changed(dialog, text):
    """Handle binary path change."""
    dialog.binary_path = text
