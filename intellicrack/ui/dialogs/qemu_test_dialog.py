"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

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

from intellicrack.handlers.pyqt6_handler import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    Qt,
    QTextEdit,
    QVBoxLayout,
)

"""QEMU test confirmation dialog."""


class QEMUTestDialog(QDialog):
    """Dialog asking user if they want to test script in QEMU first."""

    def __init__(
        self, script_type: str, target_binary: str, script_preview: str = "", parent=None
    ) -> None:
        """Initialize the QEMUTestDialog with default values."""
        super().__init__(parent)
        self.script_type = script_type
        self.target_binary = target_binary
        self.script_preview = script_preview
        self.user_choice = None

        self.setWindowTitle("Script Execution Safety Check")
        self.setModal(True)
        self.setMinimumWidth(600)

        self._init_ui()

    def _init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)

        # Header with icon and warning
        header_layout = QHBoxLayout()

        # Warning icon
        icon_label = QLabel()
        icon_label.setPixmap(
            self.style()
            .standardPixmap(
                self.style().SP_MessageBoxWarning,
            )
            .scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation),
        )
        header_layout.addWidget(icon_label)

        # Warning text
        warning_text = QLabel(
            f"<b>About to execute {self.script_type.upper()} script</b><br>"
            f"Target: {os.path.basename(self.target_binary)}<br><br>"
            "This script will interact with the target binary. "
            "Would you like to test it in a safe QEMU environment first?",
        )
        warning_text.setWordWrap(True)
        header_layout.addWidget(warning_text, 1)

        layout.addLayout(header_layout)
        layout.addSpacing(10)

        # Script preview section
        if self.script_preview:
            preview_group = QGroupBox("Script Preview")
            preview_layout = QVBoxLayout(preview_group)

            preview_text = QTextEdit()
            preview_text.setPlainText(self.script_preview)
            preview_text.setReadOnly(True)
            preview_text.setMaximumHeight(150)
            preview_text.setStyleSheet("""
                QTextEdit {
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 10pt;
                    background-color: #2b2b2b;
                    color: #e0e0e0;
                    border: 1px solid #555;
                }
            """)
            preview_layout.addWidget(preview_text)

            layout.addWidget(preview_group)
            layout.addSpacing(10)

        # Options section
        options_group = QGroupBox("Execution Options")
        options_layout = QVBoxLayout(options_group)

        self.button_group = QButtonGroup(self)

        # Option 1: Test in QEMU first (recommended)
        self.qemu_test_radio = QRadioButton("Test in QEMU first (Recommended)")
        self.qemu_test_radio.setChecked(True)
        self.qemu_test_radio.setStyleSheet("QRadioButton { font-weight: bold; color: #4CAF50; }")
        self.button_group.addButton(self.qemu_test_radio, 0)
        options_layout.addWidget(self.qemu_test_radio)

        qemu_desc = QLabel("    Safe environment to test script behavior before host execution")
        qemu_desc.setStyleSheet("color: #888;")
        options_layout.addWidget(qemu_desc)
        options_layout.addSpacing(5)

        # Option 2: Run directly on host
        self.host_run_radio = QRadioButton("Run directly on host system")
        self.host_run_radio.setStyleSheet("QRadioButton { color: #ff9800; }")
        self.button_group.addButton(self.host_run_radio, 1)
        options_layout.addWidget(self.host_run_radio)

        host_desc = QLabel("    Execute immediately without testing (experienced users)")
        host_desc.setStyleSheet("color: #888;")
        options_layout.addWidget(host_desc)

        layout.addWidget(options_group)
        layout.addSpacing(10)

        # Remember preference section
        self.remember_checkbox = QCheckBox("Remember my choice for this script type")
        layout.addWidget(self.remember_checkbox)

        # QEMU benefits info
        benefits_text = QLabel(
            "<b>Benefits of QEMU testing:</b><br>"
            "• Isolates script execution from host system<br>"
            "• Shows script behavior before deployment<br>"
            "• Prevents potential system damage<br>"
            "• Allows safe experimentation",
        )
        benefits_text.setStyleSheet("""
            QLabel {
                background-color: #e3f2fd;
                padding: 10px;
                border: 1px solid #2196f3;
                border-radius: 4px;
            }
        """)
        benefits_text.setWordWrap(True)
        layout.addWidget(benefits_text)

        layout.addStretch()

        # Button row
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        # Cancel button
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        # Continue button
        self.continue_btn = QPushButton("Continue")
        self.continue_btn.clicked.connect(self._on_continue)
        self.continue_btn.setDefault(True)
        self.continue_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(self.continue_btn)

        layout.addLayout(button_layout)

    def _on_continue(self) -> None:
        """Handle continue button click."""
        if self.qemu_test_radio.isChecked():
            if self.remember_checkbox.isChecked():
                self.user_choice = "always_test"
            else:
                self.user_choice = "test_qemu"
        elif self.remember_checkbox.isChecked():
            self.user_choice = "never_test"
        else:
            self.user_choice = "run_host"

        self.accept()

    def get_user_choice(self) -> str:
        """Get the user's choice."""
        return self.user_choice or "cancelled"
