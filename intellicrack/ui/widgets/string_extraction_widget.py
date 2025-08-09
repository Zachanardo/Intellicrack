"""String Extraction Widget for Protection Analysis

Provides string extraction and analysis capabilities integrated with
the Intellicrack Protection Engine. Helps identify hardcoded values,
license keys, and other important strings.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import re

from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QAction, QBrush, QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...utils.logger import get_logger

logger = get_logger(__name__)


class StringExtractionThread(QThread):
    """Thread for extracting strings from binary files"""

    #: List of (offset, string, encoding) (type: list)
    strings_found = pyqtSignal(list)
    progress_update = pyqtSignal(int)
    error_occurred = pyqtSignal(str)
    status_update = pyqtSignal(str)

    def __init__(
        self,
        file_path: str,
        min_length: int = 4,
        extract_unicode: bool = True,
        extract_ascii: bool = True,
    ):
        """Initialize string extraction thread with file path and extraction parameters."""
        super().__init__()
        self.file_path = file_path
        self.min_length = min_length
        self.extract_unicode = extract_unicode
        self.extract_ascii = extract_ascii
        self.logger = get_logger(__name__)

    def run(self):
        """Extract readable strings from binary file in background thread.

        Reads the binary file and extracts both ASCII and Unicode strings
        based on the configured settings. Filters strings by minimum length
        and emits progress updates during extraction.

        The extraction process handles large files efficiently and categorizes
        strings by their encoding type (ASCII, UTF-16LE, UTF-16BE).

        Emits:
            status_update: Progress messages during extraction
            strings_extracted: List of tuples (offset, string, encoding)
            extraction_error: Error message if extraction fails
        """
        try:
            strings = []
            file_size = os.path.getsize(self.file_path)
            self.logger.debug("Processing file of size: %d bytes", file_size)

            with open(self.file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            if self.extract_ascii:
                self.status_update.emit("Extracting ASCII strings...")
                ascii_strings = self._extract_ascii_strings(data)
                strings.extend([(off, s, "ASCII") for off, s in ascii_strings])
                self.progress_update.emit(50)

            # Extract Unicode strings
            if self.extract_unicode:
                self.status_update.emit("Extracting Unicode strings...")
                unicode_strings = self._extract_unicode_strings(data)
                strings.extend([(off, s, "Unicode") for off, s in unicode_strings])
                self.progress_update.emit(100)

            self.strings_found.emit(strings)

        except Exception as e:
            logger.error("Exception in string_extraction_widget: %s", e)
            self.error_occurred.emit(str(e))

    def _extract_ascii_strings(self, data: bytes) -> list[tuple[int, str]]:
        """Extract ASCII strings from binary data"""
        strings = []
        pattern = rb"[\x20-\x7E]{" + str(self.min_length).encode() + rb",}"

        for match in re.finditer(pattern, data):
            try:
                string = match.group().decode("ascii")
                offset = match.start()
                strings.append((offset, string))
            except Exception as e:
                logger.debug("Failed to decode ASCII string: %s", e)

        return strings

    def _extract_unicode_strings(self, data: bytes) -> list[tuple[int, str]]:
        """Extract Unicode (UTF-16LE) strings from binary data"""
        strings = []
        # Look for UTF-16LE patterns (ASCII chars with null bytes)
        pattern = rb"(?:[\x20-\x7E]\x00){" + str(self.min_length).encode() + rb",}"

        for match in re.finditer(pattern, data):
            try:
                string = match.group().decode("utf-16le")
                offset = match.start()
                strings.append((offset, string))
            except Exception as e:
                logger.debug("Failed to decode UTF-16LE string: %s", e)

        return strings


class StringExtractionWidget(QWidget):
    """String extraction widget with filtering and analysis"""

    # Signals
    #: offset, string (type: int, str)
    string_selected = pyqtSignal(int, str)
    #: export path (type: str)
    strings_exported = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize string extraction widget with empty state and UI setup."""
        super().__init__(parent)
        self.file_path: str | None = None
        self.all_strings: list[tuple[int, str, str]] = []  # offset, string, encoding
        self.filtered_strings: list[tuple[int, str, str]] = []
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Control bar
        control_layout = self._create_control_bar()
        layout.addLayout(control_layout)

        # Filter bar
        filter_layout = self._create_filter_bar()
        layout.addLayout(filter_layout)

        # String table
        self.string_table = QTableWidget()
        self.string_table.setColumnCount(5)
        self.string_table.setHorizontalHeaderLabels(
            [
                "Offset",
                "String",
                "Length",
                "Encoding",
                "Category",
            ]
        )

        # Set column widths
        header = self.string_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # String column stretches
        self.string_table.setColumnWidth(0, 100)  # Offset
        self.string_table.setColumnWidth(2, 80)  # Length
        self.string_table.setColumnWidth(3, 80)  # Encoding
        self.string_table.setColumnWidth(4, 120)  # Category

        # Enable sorting
        self.string_table.setSortingEnabled(True)

        # Context menu
        self.string_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.string_table.customContextMenuRequested.connect(self._show_context_menu)

        # Selection
        self.string_table.itemSelectionChanged.connect(self._on_selection_changed)

        layout.addWidget(self.string_table)

        # Status and progress
        status_layout = QHBoxLayout()

        self.status_label = QLabel("No strings extracted")
        self.status_label.setStyleSheet("color: #666;")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        status_layout.addWidget(self.progress_bar)

        layout.addLayout(status_layout)

        self.setLayout(layout)

    def _create_control_bar(self) -> QHBoxLayout:
        """Create control bar"""
        layout = QHBoxLayout()

        # Extraction options
        options_group = QGroupBox("Extraction Options")
        options_layout = QHBoxLayout()

        self.min_length_spin = QSpinBox()
        self.min_length_spin.setMinimum(3)
        self.min_length_spin.setMaximum(20)
        self.min_length_spin.setValue(4)
        options_layout.addWidget(QLabel("Min Length:"))
        options_layout.addWidget(self.min_length_spin)

        self.extract_ascii_cb = QCheckBox("ASCII")
        self.extract_ascii_cb.setChecked(True)
        options_layout.addWidget(self.extract_ascii_cb)

        self.extract_unicode_cb = QCheckBox("Unicode")
        self.extract_unicode_cb.setChecked(True)
        options_layout.addWidget(self.extract_unicode_cb)

        self.extract_btn = QPushButton("Extract Strings")
        self.extract_btn.clicked.connect(self.extract_strings)
        options_layout.addWidget(self.extract_btn)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Export options
        export_group = QGroupBox("Export")
        export_layout = QHBoxLayout()

        self.export_format = QComboBox()
        self.export_format.addItems(["Text", "CSV", "JSON"])
        export_layout.addWidget(self.export_format)

        self.export_btn = QPushButton("Export...")
        self.export_btn.clicked.connect(self.export_strings)
        export_layout.addWidget(self.export_btn)

        export_group.setLayout(export_layout)
        layout.addWidget(export_group)

        layout.addStretch()
        return layout

    def _create_filter_bar(self) -> QHBoxLayout:
        """Create filter bar"""
        layout = QHBoxLayout()

        # Search filter
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter strings...")
        self.search_input.textChanged.connect(self.apply_filters)
        layout.addWidget(QLabel("Filter:"))
        layout.addWidget(self.search_input)

        # Category filter
        self.category_filter = QComboBox()
        self.category_filter.addItems(
            [
                "All Categories",
                "License/Serial",
                "API Calls",
                "File Paths",
                "URLs",
                "Registry Keys",
                "Error Messages",
                "Suspicious",
                "Other",
            ]
        )
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.category_filter)

        # Encoding filter
        self.encoding_filter = QComboBox()
        self.encoding_filter.addItems(["All Encodings", "ASCII", "Unicode"])
        self.encoding_filter.currentTextChanged.connect(self.apply_filters)
        layout.addWidget(QLabel("Encoding:"))
        layout.addWidget(self.encoding_filter)

        # Length filter
        self.min_length_filter = QSpinBox()
        self.min_length_filter.setMinimum(0)
        self.min_length_filter.setMaximum(1000)
        self.min_length_filter.setValue(0)
        self.min_length_filter.valueChanged.connect(self.apply_filters)
        layout.addWidget(QLabel("Min Length:"))
        layout.addWidget(self.min_length_filter)

        layout.addStretch()
        return layout

    def load_file(self, file_path: str):
        """Load a file for string extraction"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", f"File not found: {file_path}")
            return

        self.file_path = file_path
        self.extract_strings()

    def extract_strings(self):
        """Extract strings from the current file"""
        if not self.file_path:
            return

        # Clear existing strings
        self.all_strings.clear()
        self.filtered_strings.clear()
        self.string_table.setRowCount(0)

        # Update UI
        self.extract_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_label.setText("Extracting strings...")

        # Start extraction thread
        self.extract_thread = StringExtractionThread(
            self.file_path,
            self.min_length_spin.value(),
            self.extract_unicode_cb.isChecked(),
            self.extract_ascii_cb.isChecked(),
        )

        self.extract_thread.strings_found.connect(self.on_strings_found)
        self.extract_thread.progress_update.connect(self.on_progress_update)
        self.extract_thread.error_occurred.connect(self.on_error)
        self.extract_thread.status_update.connect(self.on_status_update)
        self.extract_thread.start()

    @pyqtSlot(list)
    def on_strings_found(self, strings: list[tuple[int, str, str]]):
        """Handle extracted strings"""
        self.all_strings = strings
        self.filtered_strings = strings

        # Categorize strings
        categorized = []
        for offset, string, encoding in strings:
            category = self._categorize_string(string)
            categorized.append((offset, string, encoding, category))

        self.all_strings = categorized
        self.filtered_strings = categorized

        # Display strings
        self.display_strings(self.filtered_strings)

        # Update UI
        self.extract_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Found {len(self.all_strings)} strings")

    @pyqtSlot(int)
    def on_progress_update(self, progress: int):
        """Handle progress update"""
        self.progress_bar.setValue(progress)

    @pyqtSlot(str)
    def on_status_update(self, status: str):
        """Handle status update"""
        self.status_label.setText(status)

    @pyqtSlot(str)
    def on_error(self, error: str):
        """Handle extraction error"""
        QMessageBox.critical(self, "Extraction Error", f"Error extracting strings: {error}")
        self.extract_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Extraction failed")

    def _categorize_string(self, string: str) -> str:
        """Categorize a string based on its content"""
        string_lower = string.lower()

        # License/Serial patterns
        if any(
            pattern in string_lower
            for pattern in [
                "license",
                "serial",
                "key",
                "activation",
                "registration",
                "trial",
                "expire",
                "valid",
                "unlock",
            ]
        ):
            return "License/Serial"

        # API calls
        if any(
            api in string_lower
            for api in [
                "kernel32",
                "ntdll",
                "user32",
                "advapi32",
                "ws2_32",
                "createfile",
                "readfile",
                "writefile",
                "virtualprotect",
                "loadlibrary",
                "getprocaddress",
            ]
        ):
            return "API Calls"

        # File paths
        if any(indicator in string for indicator in ["\\", "/", ".dll", ".exe", ".sys"]):
            return "File Paths"

        # URLs
        if any(scheme in string_lower for scheme in ["http://", "https://", "ftp://", "www."]):
            return "URLs"

        # Registry keys
        if any(reg in string for reg in ["HKEY_", "SOFTWARE\\", "SYSTEM\\", "CurrentControlSet"]):
            return "Registry Keys"

        # Error messages
        if any(
            err in string_lower
            for err in [
                "error",
                "failed",
                "cannot",
                "unable",
                "invalid",
                "exception",
                "fault",
                "denied",
            ]
        ):
            return "Error Messages"

        # Suspicious strings
        if any(
            susp in string_lower
            for susp in [
                "debug",
                "crack",
                "patch",
                "bypass",
                "hack",
                "ollydbg",
                "ida",
                "x64dbg",
                "processhacker",
            ]
        ):
            return "Suspicious"

        return "Other"

    def display_strings(self, strings: list[tuple[int, str, str, str]]):
        """Display strings in the table"""
        self.string_table.setRowCount(0)

        for offset, string, encoding, category in strings:
            row = self.string_table.rowCount()
            self.string_table.insertRow(row)

            # Offset
            offset_item = QTableWidgetItem(f"0x{offset:08X}")
            offset_item.setData(Qt.UserRole, offset)
            self.string_table.setItem(row, 0, offset_item)

            # String (truncate if too long)
            display_string = string if len(string) <= 100 else string[:97] + "..."
            string_item = QTableWidgetItem(display_string)
            string_item.setData(Qt.UserRole, string)  # Store full string
            self.string_table.setItem(row, 1, string_item)

            # Length
            self.string_table.setItem(row, 2, QTableWidgetItem(str(len(string))))

            # Encoding
            self.string_table.setItem(row, 3, QTableWidgetItem(encoding))

            # Category
            category_item = QTableWidgetItem(category)

            # Color code by category
            if category == "License/Serial":
                category_item.setBackground(QBrush(QColor(200, 255, 200)))
            elif category == "Suspicious":
                category_item.setBackground(QBrush(QColor(255, 200, 200)))
            elif category == "API Calls":
                category_item.setBackground(QBrush(QColor(200, 200, 255)))

            self.string_table.setItem(row, 4, category_item)

    def apply_filters(self):
        """Apply filters to string list"""
        if not self.all_strings:
            return

        # Get filter values
        search_text = self.search_input.text().lower()
        category_filter = self.category_filter.currentText()
        encoding_filter = self.encoding_filter.currentText()
        min_length = self.min_length_filter.value()

        # Filter strings
        self.filtered_strings = []

        for offset, string, encoding, category in self.all_strings:
            # Search filter
            if search_text and search_text not in string.lower():
                continue

            # Category filter
            if category_filter != "All Categories" and category != category_filter:
                continue

            # Encoding filter
            if encoding_filter != "All Encodings" and encoding != encoding_filter:
                continue

            # Length filter
            if len(string) < min_length:
                continue

            self.filtered_strings.append((offset, string, encoding, category))

        # Update display
        self.display_strings(self.filtered_strings)

        # Update status
        self.status_label.setText(
            f"Showing {len(self.filtered_strings)} of {len(self.all_strings)} strings",
        )

    def _show_context_menu(self, position):
        """Show context menu for string table"""
        if not self.string_table.selectedItems():
            return

        menu = QMenu(self)

        # Copy actions
        copy_string_action = QAction("Copy String", self)
        copy_string_action.triggered.connect(self._copy_selected_string)
        menu.addAction(copy_string_action)

        copy_offset_action = QAction("Copy Offset", self)
        copy_offset_action.triggered.connect(self._copy_selected_offset)
        menu.addAction(copy_offset_action)

        copy_all_action = QAction("Copy Row", self)
        copy_all_action.triggered.connect(self._copy_selected_row)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        # Navigation
        goto_offset_action = QAction("Go to Offset in Hex View", self)
        goto_offset_action.triggered.connect(self._goto_selected_offset)
        menu.addAction(goto_offset_action)

        menu.exec_(self.string_table.mapToGlobal(position))

    def _copy_selected_string(self):
        """Copy selected string to clipboard"""
        row = self.string_table.currentRow()
        if row >= 0:
            string_item = self.string_table.item(row, 1)
            if string_item:
                full_string = string_item.data(Qt.UserRole)
                from intellicrack.ui.dialogs.common_imports import QApplication

                QApplication.clipboard().setText(full_string)

    def _copy_selected_offset(self):
        """Copy selected offset to clipboard"""
        row = self.string_table.currentRow()
        if row >= 0:
            offset_item = self.string_table.item(row, 0)
            if offset_item:
                

                QApplication.clipboard().setText(offset_item.text())

    def _copy_selected_row(self):
        """Copy entire selected row to clipboard"""
        row = self.string_table.currentRow()
        if row >= 0:
            row_data = []
            for col in range(self.string_table.columnCount()):
                item = self.string_table.item(row, col)
                if item:
                    if col == 1:  # String column - get full string
                        row_data.append(item.data(Qt.UserRole))
                    else:
                        row_data.append(item.text())

            

            QApplication.clipboard().setText("\t".join(row_data))

    def _goto_selected_offset(self):
        """Emit signal to go to selected offset"""
        row = self.string_table.currentRow()
        if row >= 0:
            offset_item = self.string_table.item(row, 0)
            string_item = self.string_table.item(row, 1)
            if offset_item and string_item:
                offset = offset_item.data(Qt.UserRole)
                string = string_item.data(Qt.UserRole)
                self.string_selected.emit(offset, string)

    def _on_selection_changed(self):
        """Handle selection change"""
        row = self.string_table.currentRow()
        if row >= 0:
            offset_item = self.string_table.item(row, 0)
            string_item = self.string_table.item(row, 1)
            if offset_item and string_item:
                offset = offset_item.data(Qt.UserRole)
                string = string_item.data(Qt.UserRole)
                # Emit for integration with hex viewer
                self.string_selected.emit(offset, string)

    def export_strings(self):
        """Export strings to file"""
        if not self.filtered_strings:
            QMessageBox.information(self, "No Strings", "No strings to export")
            return

        format_type = self.export_format.currentText()

        # Get file path
        if format_type == "Text":
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Strings",
                "strings.txt",
                "Text Files (*.txt)",
            )
        elif format_type == "CSV":
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Strings",
                "strings.csv",
                "CSV Files (*.csv)",
            )
        else:  # JSON
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Strings",
                "strings.json",
                "JSON Files (*.json)",
            )

        if not file_path:
            return

        try:
            if format_type == "Text":
                self._export_as_text(file_path)
            elif format_type == "CSV":
                self._export_as_csv(file_path)
            else:
                self._export_as_json(file_path)

            self.strings_exported.emit(file_path)
            QMessageBox.information(
                self,
                "Export Complete",
                f"Strings exported to:\n{file_path}",
            )

        except Exception as e:
            logger.error("Exception in string_extraction_widget: %s", e)
            QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting strings: {e!s}",
            )

    def _export_as_text(self, file_path: str):
        """Export strings as text"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("String Extraction Report\n")
            f.write(f"File: {self.file_path}\n")
            f.write(f"Total Strings: {len(self.filtered_strings)}\n")
            f.write("=" * 80 + "\n\n")

            for offset, string, encoding, category in self.filtered_strings:
                f.write(f"Offset: 0x{offset:08X}\n")
                f.write(f"Category: {category}\n")
                f.write(f"Encoding: {encoding}\n")
                f.write(f"Length: {len(string)}\n")
                f.write(f"String: {string!r}\n")
                f.write("-" * 40 + "\n")

    def _export_as_csv(self, file_path: str):
        """Export strings as CSV"""
        import csv

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Offset", "String", "Length", "Encoding", "Category"])

            for offset, string, encoding, category in self.filtered_strings:
                writer.writerow(
                    [
                        f"0x{offset:08X}",
                        string,
                        len(string),
                        encoding,
                        category,
                    ]
                )

    def _export_as_json(self, file_path: str):
        """Export strings as JSON"""
        import json

        data = {
            "file": self.file_path,
            "total_strings": len(self.filtered_strings),
            "strings": [],
        }

        for offset, string, encoding, category in self.filtered_strings:
            data["strings"].append(
                {
                    "offset": f"0x{offset:08X}",
                    "offset_decimal": offset,
                    "string": string,
                    "length": len(string),
                    "encoding": encoding,
                    "category": category,
                }
            )

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
