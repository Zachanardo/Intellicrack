"""File Comparison Dialog for Hex Viewer.

This module provides a dialog for selecting two files to compare
and displays the comparison results in a side-by-side view.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ComparisonWorker(QThread):
    """Worker thread for running file comparison in background."""

    progress = pyqtSignal(int, int)  # current, total
    finished = pyqtSignal(list)  # differences list
    error = pyqtSignal(str)  # error message

    def __init__(self, comparer, file1_path: str, file2_path: str) -> None:
        """Initialize the worker.

        Args:
            comparer: BinaryComparer instance
            file1_path: Path to first file
            file2_path: Path to second file

        """
        super().__init__()
        self.comparer = comparer
        self.file1_path = file1_path
        self.file2_path = file2_path

    def run(self) -> None:
        """Run the comparison."""
        try:
            # Set progress callback
            self.comparer.set_progress_callback(self.progress.emit)

            # Run comparison
            differences = self.comparer.compare_files(self.file1_path, self.file2_path)

            # Emit results
            self.finished.emit(differences)

        except Exception as e:
            self.error.emit(str(e))


class CompareDialog(QDialog):
    """Dialog for selecting and comparing two binary files."""

    def __init__(self, parent=None, initial_file: Optional[str] = None) -> None:
        """Initialize the compare dialog.

        Args:
            parent: Parent widget
            initial_file: Path to pre-populate as first file

        """
        super().__init__(parent)
        self.file1_path = initial_file or ""
        self.file2_path = ""
        self.comparison_mode = "visual"  # visual, byte, or structural
        self.sync_scrolling = True
        self.highlight_differences = True

        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle("Compare Files")
        self.setModal(True)
        self.resize(700, 500)

        layout = QVBoxLayout(self)

        # File selection section
        file_group = QGroupBox("Select Files to Compare")
        file_layout = QVBoxLayout()

        # File 1
        file1_layout = QHBoxLayout()
        file1_label = QLabel("File 1:")
        file1_label.setFixedWidth(60)
        self.file1_edit = QLineEdit(self.file1_path)
        self.file1_edit.setReadOnly(True)
        file1_button = QPushButton("Browse...")
        file1_button.clicked.connect(lambda: self.browse_file(1))

        file1_layout.addWidget(file1_label)
        file1_layout.addWidget(self.file1_edit)
        file1_layout.addWidget(file1_button)
        file_layout.addLayout(file1_layout)

        # File 1 info
        self.file1_info = QLabel("No file selected")
        self.file1_info.setStyleSheet("color: gray; margin-left: 65px;")
        file_layout.addWidget(self.file1_info)

        # Spacer
        file_layout.addSpacing(10)

        # File 2
        file2_layout = QHBoxLayout()
        file2_label = QLabel("File 2:")
        file2_label.setFixedWidth(60)
        self.file2_edit = QLineEdit(self.file2_path)
        self.file2_edit.setReadOnly(True)
        file2_button = QPushButton("Browse...")
        file2_button.clicked.connect(lambda: self.browse_file(2))

        file2_layout.addWidget(file2_label)
        file2_layout.addWidget(self.file2_edit)
        file2_layout.addWidget(file2_button)
        file_layout.addLayout(file2_layout)

        # File 2 info
        self.file2_info = QLabel("No file selected")
        self.file2_info.setStyleSheet("color: gray; margin-left: 65px;")
        file_layout.addWidget(self.file2_info)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Comparison options
        options_group = QGroupBox("Comparison Options")
        options_layout = QVBoxLayout()

        # Comparison mode
        mode_label = QLabel("Comparison Mode:")
        mode_label.setStyleSheet("font-weight: bold;")
        options_layout.addWidget(mode_label)

        self.mode_group = QButtonGroup()

        mode_visual = QRadioButton("Visual (Side-by-side hex view)")
        mode_visual.setChecked(True)
        mode_visual.toggled.connect(lambda checked: self.set_mode("visual") if checked else None)
        self.mode_group.addButton(mode_visual)
        options_layout.addWidget(mode_visual)

        mode_byte = QRadioButton("Byte-by-byte (Detailed difference list)")
        mode_byte.toggled.connect(lambda checked: self.set_mode("byte") if checked else None)
        self.mode_group.addButton(mode_byte)
        options_layout.addWidget(mode_byte)

        mode_structural = QRadioButton("Structural (Block-level changes)")
        mode_structural.toggled.connect(lambda checked: self.set_mode("structural") if checked else None)
        self.mode_group.addButton(mode_structural)
        options_layout.addWidget(mode_structural)

        # View options
        options_layout.addSpacing(10)
        view_label = QLabel("View Options:")
        view_label.setStyleSheet("font-weight: bold;")
        options_layout.addWidget(view_label)

        self.sync_check = QCheckBox("Synchronize scrolling")
        self.sync_check.setChecked(self.sync_scrolling)
        self.sync_check.toggled.connect(self.toggle_sync_scrolling)
        options_layout.addWidget(self.sync_check)

        self.highlight_check = QCheckBox("Highlight differences")
        self.highlight_check.setChecked(self.highlight_differences)
        self.highlight_check.toggled.connect(self.toggle_highlight)
        options_layout.addWidget(self.highlight_check)

        self.ignore_case_check = QCheckBox("Ignore case in ASCII view")
        options_layout.addWidget(self.ignore_case_check)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Statistics label (hidden initially)
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("color: blue; font-weight: bold;")
        self.stats_label.hide()
        layout.addWidget(self.stats_label)

        # Button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        # Update file info if initial file was provided
        if self.file1_path:
            self.update_file_info(1)

    def browse_file(self, file_num: int) -> None:
        """Browse for a file to compare.

        Args:
            file_num: 1 or 2 for first or second file

        """
        file_path, _ = QFileDialog.getOpenFileName(self, f"Select File {file_num}", "", "All Files (*.*)")

        if file_path:
            if file_num == 1:
                self.file1_path = file_path
                self.file1_edit.setText(file_path)
                self.update_file_info(1)
            else:
                self.file2_path = file_path
                self.file2_edit.setText(file_path)
                self.update_file_info(2)

    def update_file_info(self, file_num: int) -> None:
        """Update file information display.

        Args:
            file_num: 1 or 2 for first or second file

        """
        if file_num == 1:
            path = self.file1_path
            label = self.file1_info
        else:
            path = self.file2_path
            label = self.file2_info

        if not path or not os.path.exists(path):
            label.setText("No file selected")
            label.setStyleSheet("color: gray; margin-left: 65px;")
            return

        try:
            size = os.path.getsize(path)

            # Format size
            if size < 1024:
                size_str = f"{size} bytes"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.2f} KB"
            elif size < 1024 * 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.2f} MB"
            else:
                size_str = f"{size / (1024 * 1024 * 1024):.2f} GB"

            # Get file name
            filename = os.path.basename(path)

            label.setText(f"Size: {size_str} | Name: {filename}")
            label.setStyleSheet("color: green; margin-left: 65px;")

        except Exception as e:
            label.setText(f"Error: {e!s}")
            label.setStyleSheet("color: red; margin-left: 65px;")

    def set_mode(self, mode: str) -> None:
        """Set comparison mode.

        Args:
            mode: Comparison mode (visual, byte, or structural)

        """
        self.comparison_mode = mode

    def toggle_sync_scrolling(self, checked: bool) -> None:
        """Toggle synchronized scrolling.

        Args:
            checked: Whether sync scrolling is enabled

        """
        self.sync_scrolling = checked

    def toggle_highlight(self, checked: bool) -> None:
        """Toggle difference highlighting.

        Args:
            checked: Whether highlighting is enabled

        """
        self.highlight_differences = checked

    def validate_selection(self) -> bool:
        """Validate that two valid files are selected.

        Returns:
            True if selection is valid

        """
        if not self.file1_path or not self.file2_path:
            QMessageBox.warning(self, "Selection Required", "Please select two files to compare.")
            return False

        if not os.path.exists(self.file1_path):
            QMessageBox.warning(self, "File Not Found", f"File 1 not found: {self.file1_path}")
            return False

        if not os.path.exists(self.file2_path):
            QMessageBox.warning(self, "File Not Found", f"File 2 not found: {self.file2_path}")
            return False

        if self.file1_path == self.file2_path:
            QMessageBox.warning(self, "Same File", "Please select two different files to compare.")
            return False

        return True

    def accept(self) -> None:
        """Accept the dialog if validation passes."""
        if self.validate_selection():
            super().accept()

    def get_settings(self) -> dict:
        """Get the comparison settings.

        Returns:
            Dictionary with comparison settings

        """
        return {
            "file1": self.file1_path,
            "file2": self.file2_path,
            "mode": self.comparison_mode,
            "sync_scrolling": self.sync_scrolling,
            "highlight_differences": self.highlight_differences,
            "ignore_case": self.ignore_case_check.isChecked(),
        }

    def show_quick_stats(self, differences: list) -> None:
        """Show quick statistics about the comparison.

        Args:
            differences: List of DifferenceBlock objects

        """
        if not differences:
            self.stats_label.setText("Files are identical")
            self.stats_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            modified = sum(1 for d in differences if str(d.diff_type) == "DifferenceType.MODIFIED")
            inserted = sum(1 for d in differences if str(d.diff_type) == "DifferenceType.INSERTED")
            deleted = sum(1 for d in differences if str(d.diff_type) == "DifferenceType.DELETED")

            stats_text = f"Found {len(differences)} difference blocks: "
            parts = []
            if modified:
                parts.append(f"{modified} modified")
            if inserted:
                parts.append(f"{inserted} inserted")
            if deleted:
                parts.append(f"{deleted} deleted")

            stats_text += ", ".join(parts)
            self.stats_label.setText(stats_text)
            self.stats_label.setStyleSheet("color: orange; font-weight: bold;")

        self.stats_label.show()
