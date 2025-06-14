"""
Base dialog classes for common UI patterns in Intellicrack.

This module provides base classes to reduce code duplication in dialogs.
"""


try:
    from PyQt5.QtWidgets import QDialog, QFileDialog, QGroupBox, QHBoxLayout, QLineEdit, QPushButton
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False
    QDialog = object


class BinarySelectionDialog(QDialog if HAS_PYQT else object):
    """Base dialog class for dialogs that need binary file selection."""

    def __init__(self, parent=None, binary_path: str = ""):
        if HAS_PYQT:
            super().__init__(parent)
        self.binary_path = binary_path
        self.binary_path_edit = None
        self.browse_btn = None

    def setup_header(self, layout, show_label=True, extra_buttons=None):
        """
        Setup header with binary selection.
        
        Args:
            layout: Parent layout to add header to
            show_label: Whether to show "Binary Path:" label
            extra_buttons: List of (button_text, callback) tuples for additional buttons
        """
        if not HAS_PYQT:
            return

        header_group = QGroupBox("Target Binary")
        header_layout = QHBoxLayout(header_group)

        if show_label:
            from PyQt5.QtWidgets import QLabel
            header_layout.addWidget(QLabel("Binary Path:"))

        self.binary_path_edit = QLineEdit(self.binary_path)
        self.binary_path_edit.setPlaceholderText("Select target binary file...")

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_binary)

        header_layout.addWidget(self.binary_path_edit)
        header_layout.addWidget(self.browse_btn)

        # Add any extra buttons
        if extra_buttons:
            from ...utils.ui_button_common import add_extra_buttons
            buttons = add_extra_buttons(header_layout, extra_buttons, {'analyze_btn': None})
            if 'Analyze Binary' in buttons:
                self.analyze_btn = buttons['Analyze Binary']

        layout.addWidget(header_group)

    def browse_binary(self):
        """Browse for binary file."""
        if not HAS_PYQT:
            return

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*.*)"
        )

        if filename:
            self.binary_path = filename
            self.binary_path_edit.setText(filename)
            self.on_binary_selected(filename)

    def on_binary_selected(self, filename: str):
        """Called when a binary is selected. Override in subclasses."""
        pass
