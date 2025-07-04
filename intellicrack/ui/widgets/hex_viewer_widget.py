"""
Hex Viewer Widget for Protection Analysis

Provides hex view capabilities integrated with the Intellicrack Protection Engine.
Supports navigation, search, and highlighting of important binary regions.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
from typing import List, Optional, Tuple

from PyQt5.QtCore import QModelIndex, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QBrush, QColor, QFont, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from ...utils.logger import get_logger
from .pe_file_model import PEFileModel, create_file_model
from .pe_structure_model import PEStructureModel

logger = get_logger(__name__)


class HexViewerThread(QThread):
    """Thread for loading large binary files"""
    data_loaded = pyqtSignal(bytes)
    progress_update = pyqtSignal(int)
    error_occurred = pyqtSignal(str)

    def __init__(self, file_path: str, offset: int = 0, size: Optional[int] = None):
        super().__init__()
        self.file_path = file_path
        self.offset = offset
        self.size = size

    def run(self):
        try:
            file_size = os.path.getsize(self.file_path)

            # Limit size to prevent memory issues
            max_size = 10 * 1024 * 1024  # 10MB max
            if self.size is None or self.size > max_size:
                self.size = min(file_size - self.offset, max_size)

            with open(self.file_path, 'rb') as f:
                f.seek(self.offset)

                # Read in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                data = bytearray()
                bytes_read = 0

                while bytes_read < self.size:
                    chunk = f.read(min(chunk_size, self.size - bytes_read))
                    if not chunk:
                        break

                    data.extend(chunk)
                    bytes_read += len(chunk)

                    progress = int((bytes_read / self.size) * 100)
                    self.progress_update.emit(progress)

                self.data_loaded.emit(bytes(data))

        except Exception as e:
            logger.error("Exception in hex_viewer_widget: %s", e)
            self.error_occurred.emit(str(e))


class HexViewerWidget(QWidget):
    """
    Hex viewer widget with protection analysis integration
    """

    # Signals
    offset_selected = pyqtSignal(int)  # Offset clicked
    region_highlighted = pyqtSignal(int, int)  # Start, end offsets

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_path: Optional[str] = None
        self.file_data: Optional[bytes] = None
        self.current_offset = 0
        self.bytes_per_line = 16
        self.highlighted_regions: List[Tuple[int, int, QColor]] = []

        # PE analysis components
        self.file_model: Optional[PEFileModel] = None
        self.structure_model: Optional[PEStructureModel] = None

        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Control bar
        control_layout = self._create_control_bar()
        layout.addLayout(control_layout)

        # Main area with horizontal splitter
        main_splitter = QSplitter(Qt.Horizontal)

        # Left side: PE Structure Tree
        left_panel = self._create_structure_panel()
        main_splitter.addWidget(left_panel)

        # Right side: Hex view and info
        right_splitter = QSplitter(Qt.Horizontal)

        # Hex display
        self.hex_display = QTextEdit()
        self.hex_display.setReadOnly(True)
        self.hex_display.setFont(QFont("Consolas", 10))
        self.hex_display.setLineWrapMode(QTextEdit.NoWrap)
        right_splitter.addWidget(self.hex_display)

        # ASCII display
        self.ascii_display = QTextEdit()
        self.ascii_display.setReadOnly(True)
        self.ascii_display.setFont(QFont("Consolas", 10))
        self.ascii_display.setLineWrapMode(QTextEdit.NoWrap)
        right_splitter.addWidget(self.ascii_display)

        # Info panel
        self.info_panel = self._create_info_panel()
        right_splitter.addWidget(self.info_panel)

        right_splitter.setSizes([400, 200, 200])
        main_splitter.addWidget(right_splitter)

        # Set splitter proportions: 25% tree, 75% hex view
        main_splitter.setSizes([250, 750])
        layout.addWidget(main_splitter)

        # Status bar
        self.status_label = QLabel("No file loaded")
        self.status_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def _create_control_bar(self) -> QHBoxLayout:
        """Create control bar with navigation and search"""
        layout = QHBoxLayout()

        # Navigation
        nav_group = QGroupBox("Navigation")
        nav_layout = QHBoxLayout()

        self.offset_spin = QSpinBox()
        self.offset_spin.setPrefix("0x")
        self.offset_spin.setDisplayIntegerBase(16)
        self.offset_spin.valueChanged.connect(self.go_to_offset)
        nav_layout.addWidget(QLabel("Offset:"))
        nav_layout.addWidget(self.offset_spin)

        self.goto_btn = QPushButton("Go")
        self.goto_btn.clicked.connect(lambda: self.go_to_offset(self.offset_spin.value()))
        nav_layout.addWidget(self.goto_btn)

        # RVA navigation
        nav_layout.addWidget(QLabel("RVA:"))
        self.rva_spin = QSpinBox()
        self.rva_spin.setPrefix("0x")
        self.rva_spin.setDisplayIntegerBase(16)
        self.rva_spin.setMaximum(0xFFFFFFFF)
        self.rva_spin.valueChanged.connect(self.go_to_rva)
        nav_layout.addWidget(self.rva_spin)

        self.goto_rva_btn = QPushButton("Go RVA")
        self.goto_rva_btn.clicked.connect(lambda: self.go_to_rva(self.rva_spin.value()))
        nav_layout.addWidget(self.goto_rva_btn)

        nav_group.setLayout(nav_layout)
        layout.addWidget(nav_group)

        # Search
        search_group = QGroupBox("Search")
        search_layout = QHBoxLayout()

        self.search_type = QComboBox()
        self.search_type.addItems(["Hex", "ASCII", "Unicode"])
        search_layout.addWidget(self.search_type)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search pattern...")
        self.search_input.returnPressed.connect(self.search_data)
        search_layout.addWidget(self.search_input)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.search_data)
        search_layout.addWidget(self.search_btn)

        search_group.setLayout(search_layout)
        layout.addWidget(search_group)

        # Display options
        options_group = QGroupBox("Display")
        options_layout = QHBoxLayout()

        self.bytes_per_line_spin = QSpinBox()
        self.bytes_per_line_spin.setMinimum(8)
        self.bytes_per_line_spin.setMaximum(32)
        self.bytes_per_line_spin.setSingleStep(8)
        self.bytes_per_line_spin.setValue(16)
        self.bytes_per_line_spin.valueChanged.connect(self.update_display)
        options_layout.addWidget(QLabel("Bytes/Line:"))
        options_layout.addWidget(self.bytes_per_line_spin)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()
        return layout

    def _create_structure_panel(self) -> QWidget:
        """Create PE structure tree panel"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Structure tree controls
        controls_layout = QHBoxLayout()

        self.show_structure_cb = QCheckBox("Show PE Structure")
        self.show_structure_cb.setChecked(True)
        self.show_structure_cb.toggled.connect(self._on_structure_visibility_changed)
        controls_layout.addWidget(self.show_structure_cb)

        self.expand_all_btn = QPushButton("Expand All")
        self.expand_all_btn.clicked.connect(self._expand_all_structures)
        controls_layout.addWidget(self.expand_all_btn)

        self.collapse_all_btn = QPushButton("Collapse All")
        self.collapse_all_btn.clicked.connect(self._collapse_all_structures)
        controls_layout.addWidget(self.collapse_all_btn)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # PE Structure Tree
        self.structure_tree = QTreeView()
        self.structure_tree.setHeaderHidden(False)
        self.structure_tree.setAlternatingRowColors(True)
        self.structure_tree.setExpandsOnDoubleClick(True)
        self.structure_tree.clicked.connect(self._on_structure_clicked)
        self.structure_tree.doubleClicked.connect(self._on_structure_double_clicked)
        layout.addWidget(self.structure_tree)

        # Structure info
        structure_info_group = QGroupBox("Structure Info")
        info_layout = QVBoxLayout()

        self.structure_info_text = QTextEdit()
        self.structure_info_text.setReadOnly(True)
        self.structure_info_text.setMaximumHeight(100)
        self.structure_info_text.setFont(QFont("Consolas", 9))
        info_layout.addWidget(self.structure_info_text)

        structure_info_group.setLayout(info_layout)
        layout.addWidget(structure_info_group)

        widget.setLayout(layout)
        return widget

    def _create_info_panel(self) -> QWidget:
        """Create information panel"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Selection info
        selection_group = QGroupBox("Selection")
        selection_layout = QVBoxLayout()

        self.selection_info = QTextEdit()
        self.selection_info.setReadOnly(True)
        self.selection_info.setMaximumHeight(150)
        self.selection_info.setFont(QFont("Consolas", 9))
        selection_layout.addWidget(self.selection_info)

        selection_group.setLayout(selection_layout)
        layout.addWidget(selection_group)

        # Data interpreter
        interpreter_group = QGroupBox("Data Interpreter")
        interpreter_layout = QVBoxLayout()

        self.interpreter_table = QTableWidget()
        self.interpreter_table.setColumnCount(2)
        self.interpreter_table.setHorizontalHeaderLabels(["Type", "Value"])
        self.interpreter_table.horizontalHeader().setStretchLastSection(True)
        self.interpreter_table.setAlternatingRowColors(True)
        interpreter_layout.addWidget(self.interpreter_table)

        interpreter_group.setLayout(interpreter_layout)
        layout.addWidget(interpreter_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def load_file(self, file_path: str, offset: int = 0, size: Optional[int] = None):
        """Load a binary file with PE analysis"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", f"File not found: {file_path}")
            return

        self.file_path = file_path
        self.current_offset = offset

        # Update status
        self.status_label.setText(f"Loading {os.path.basename(file_path)}...")

        # Try to create PE file model for analysis
        try:
            self.file_model = create_file_model(file_path)
            if self.file_model:
                # Set up structure model
                self.structure_model = PEStructureModel(self.file_model)
                self.structure_tree.setModel(self.structure_model)

                # Connect signals
                self.structure_model.structure_selected.connect(self._on_structure_navigation)
                self.structure_model.rva_selected.connect(self._on_rva_navigation)

                # Enable RVA controls
                self.rva_spin.setEnabled(True)
                self.goto_rva_btn.setEnabled(True)

                # Update RVA range
                if isinstance(self.file_model, PEFileModel):
                    # Set RVA range based on image base
                    image_base = self.file_model.image_base
                    self.rva_spin.setMaximum(image_base + self.file_model.file_size)

                logger.info(f"PE analysis successful for {file_path}")
            else:
                # Not a PE file or analysis failed
                self._clear_structure_view()
                logger.info(f"File {file_path} is not a supported format for structure analysis")

        except Exception as e:
            logger.warning(f"PE analysis failed for {file_path}: {e}")
            self._clear_structure_view()

        # Start loading thread
        self.load_thread = HexViewerThread(file_path, offset, size)
        self.load_thread.data_loaded.connect(self.on_data_loaded)
        self.load_thread.progress_update.connect(self.on_load_progress)
        self.load_thread.error_occurred.connect(self.on_load_error)
        self.load_thread.start()

    @pyqtSlot(bytes)
    def on_data_loaded(self, data: bytes):
        """Handle loaded data"""
        self.file_data = data

        # Update offset spinner range
        if self.file_path:
            file_size = os.path.getsize(self.file_path)
            self.offset_spin.setMaximum(file_size - 1)

        # Update display
        self.update_display()

        # Update status
        self.status_label.setText(
            f"Loaded: {os.path.basename(self.file_path)} "
            f"({len(data):,} bytes from offset 0x{self.current_offset:X})"
        )

    @pyqtSlot(int)
    def on_load_progress(self, progress: int):
        """Handle load progress"""
        self.status_label.setText(
            f"Loading {os.path.basename(self.file_path)}... {progress}%"
        )

    @pyqtSlot(str)
    def on_load_error(self, error: str):
        """Handle load error"""
        QMessageBox.critical(self, "Load Error", f"Error loading file: {error}")
        self.status_label.setText("Load failed")

    def update_display(self):
        """Update hex and ASCII displays"""
        if not self.file_data:
            return

        self.bytes_per_line = self.bytes_per_line_spin.value()

        # Clear displays
        self.hex_display.clear()
        self.ascii_display.clear()

        hex_lines = []
        ascii_lines = []

        for i in range(0, len(self.file_data), self.bytes_per_line):
            # Offset
            offset = self.current_offset + i
            offset_str = f"{offset:08X}: "

            # Hex values
            hex_values = []
            ascii_values = []

            for j in range(self.bytes_per_line):
                if i + j < len(self.file_data):
                    byte = self.file_data[i + j]
                    hex_values.append(f"{byte:02X}")

                    # ASCII representation
                    if 32 <= byte <= 126:
                        ascii_values.append(chr(byte))
                    else:
                        ascii_values.append(".")
                else:
                    hex_values.append("  ")
                    ascii_values.append(" ")

            # Format hex with spacing
            hex_line = offset_str
            for k in range(0, len(hex_values), 4):
                hex_line += " ".join(hex_values[k:k+4]) + "  "

            hex_lines.append(hex_line.rstrip())
            ascii_lines.append("".join(ascii_values))

        # Set text
        self.hex_display.setPlainText("\n".join(hex_lines))
        self.ascii_display.setPlainText("\n".join(ascii_lines))

        # Apply highlighting
        self.apply_highlighting()

    def apply_highlighting(self):
        """Apply highlighting to regions"""
        for start, end, color in self.highlighted_regions:
            self.highlight_region(start, end, color)

    def highlight_region(self, start: int, end: int, color: QColor):
        """Highlight a region in the hex view"""
        if not self.file_data:
            return

        # Calculate line positions
        start_line = (start - self.current_offset) // self.bytes_per_line
        end_line = (end - self.current_offset) // self.bytes_per_line

        if start_line < 0 or end_line >= len(self.file_data) // self.bytes_per_line:
            return

        # Create format
        fmt = QTextCharFormat()
        fmt.setBackground(QBrush(color))

        # Apply to hex display
        cursor = self.hex_display.textCursor()
        cursor.movePosition(QTextCursor.Start)

        # Move to start line
        for _ in range(start_line):
            cursor.movePosition(QTextCursor.Down)

        # Highlight bytes
        # Implementation depends on exact formatting

    def go_to_offset(self, offset: int):
        """Navigate to specific offset"""
        if self.file_path and 0 <= offset < os.path.getsize(self.file_path):
            self.load_file(self.file_path, offset)
            self.offset_selected.emit(offset)

    def go_to_rva(self, rva: int):
        """Navigate to specific RVA"""
        if not self.file_model:
            QMessageBox.warning(self, "No PE Analysis", "RVA navigation requires PE file analysis")
            return

        # Convert RVA to file offset
        offset = self.file_model.rva_to_offset(rva)
        if offset is not None:
            self.go_to_offset(offset)
            # Update info
            self.structure_info_text.clear()
            self.structure_info_text.append(f"RVA: 0x{rva:X}")
            self.structure_info_text.append(f"File Offset: 0x{offset:X}")

            # Find which section contains this RVA
            section = self.file_model.get_section_at_rva(rva)
            if section:
                self.structure_info_text.append(f"Section: {section.name}")
                self.structure_info_text.append(f"Section Offset: 0x{rva - section.virtual_address:X}")
        else:
            QMessageBox.warning(self, "Invalid RVA", f"RVA 0x{rva:X} is not valid for this file")

    def search_data(self):
        """Search for pattern in data"""
        if not self.file_data:
            return

        pattern = self.search_input.text()
        if not pattern:
            return

        search_type = self.search_type.currentText()

        try:
            if search_type == "Hex":
                # Convert hex string to bytes
                pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
            elif search_type == "ASCII":
                pattern_bytes = pattern.encode('ascii')
            else:  # Unicode
                pattern_bytes = pattern.encode('utf-16le')

            # Search for pattern
            index = self.file_data.find(pattern_bytes)
            if index != -1:
                # Found - navigate to offset
                found_offset = self.current_offset + index
                self.go_to_offset(found_offset)

                # Highlight found data
                self.highlighted_regions.append(
                    (found_offset, found_offset + len(pattern_bytes), QColor(255, 255, 0, 100))
                )
                self.update_display()

                QMessageBox.information(
                    self,
                    "Search Result",
                    f"Pattern found at offset 0x{found_offset:X}"
                )
            else:
                QMessageBox.information(
                    self,
                    "Search Result",
                    "Pattern not found in current view"
                )

        except Exception as e:
            logger.error("Exception in hex_viewer_widget: %s", e)
            QMessageBox.warning(
                self,
                "Search Error",
                f"Invalid search pattern: {str(e)}"
            )

    def add_protection_highlight(self, offset: int, size: int, protection_name: str):
        """Add highlighting for detected protection region"""
        # Choose color based on protection type
        if "pack" in protection_name.lower():
            color = QColor(255, 200, 200, 100)  # Light red for packers
        elif "crypt" in protection_name.lower():
            color = QColor(200, 200, 255, 100)  # Light blue for cryptors
        elif "license" in protection_name.lower():
            color = QColor(200, 255, 200, 100)  # Light green for licensing
        else:
            color = QColor(255, 255, 200, 100)  # Light yellow for others

        self.highlighted_regions.append((offset, offset + size, color))

        # Update selection info
        info = f"Protection: {protection_name}\n"
        info += f"Offset: 0x{offset:X}\n"
        info += f"Size: {size} bytes (0x{size:X})\n"
        self.selection_info.append(info)

        # Refresh display
        self.update_display()

    def interpret_data_at_cursor(self):
        """Interpret data at current cursor position"""
        cursor = self.hex_display.textCursor()
        position = cursor.position()

        self.logger.debug("Cursor position: %d", position)

        # Calculate byte offset from cursor position
        # This is complex due to formatting - simplified version
        line = cursor.blockNumber()
        byte_offset = line * self.bytes_per_line

        if byte_offset < len(self.file_data):
            self.interpret_bytes(byte_offset)

    def interpret_bytes(self, offset: int):
        """Interpret bytes at offset as various data types"""
        if not self.file_data or offset >= len(self.file_data):
            return

        self.interpreter_table.setRowCount(0)

        # Get available bytes
        available = len(self.file_data) - offset

        interpretations = []

        # 8-bit values
        if available >= 1:
            byte_val = self.file_data[offset]
            interpretations.append(("UInt8", str(byte_val)))
            interpretations.append(("Int8", str(struct.unpack('b', bytes([byte_val]))[0])))
            interpretations.append(("Char", repr(chr(byte_val)) if 32 <= byte_val <= 126 else "N/A"))

        # 16-bit values
        if available >= 2:
            data = self.file_data[offset:offset+2]
            interpretations.append(("UInt16 LE", str(struct.unpack('<H', data)[0])))
            interpretations.append(("UInt16 BE", str(struct.unpack('>H', data)[0])))
            interpretations.append(("Int16 LE", str(struct.unpack('<h', data)[0])))
            interpretations.append(("Int16 BE", str(struct.unpack('>h', data)[0])))

        # 32-bit values
        if available >= 4:
            data = self.file_data[offset:offset+4]
            interpretations.append(("UInt32 LE", str(struct.unpack('<I', data)[0])))
            interpretations.append(("UInt32 BE", str(struct.unpack('>I', data)[0])))
            interpretations.append(("Int32 LE", str(struct.unpack('<i', data)[0])))
            interpretations.append(("Int32 BE", str(struct.unpack('>i', data)[0])))
            interpretations.append(("Float LE", f"{struct.unpack('<f', data)[0]:.6f}"))
            interpretations.append(("Float BE", f"{struct.unpack('>f', data)[0]:.6f}"))

        # 64-bit values
        if available >= 8:
            data = self.file_data[offset:offset+8]
            interpretations.append(("UInt64 LE", str(struct.unpack('<Q', data)[0])))
            interpretations.append(("UInt64 BE", str(struct.unpack('>Q', data)[0])))
            interpretations.append(("Int64 LE", str(struct.unpack('<q', data)[0])))
            interpretations.append(("Int64 BE", str(struct.unpack('>q', data)[0])))
            interpretations.append(("Double LE", f"{struct.unpack('<d', data)[0]:.10f}"))
            interpretations.append(("Double BE", f"{struct.unpack('>d', data)[0]:.10f}"))

        # Add to table
        for data_type, value in interpretations:
            row = self.interpreter_table.rowCount()
            self.interpreter_table.insertRow(row)
            self.interpreter_table.setItem(row, 0, QTableWidgetItem(data_type))
            self.interpreter_table.setItem(row, 1, QTableWidgetItem(value))

    def export_selection(self):
        """Export selected bytes to file"""
        # Get selection from hex display
        cursor = self.hex_display.textCursor()
        if not cursor.hasSelection():
            QMessageBox.information(self, "No Selection", "Please select bytes to export")
            return

        # Calculate byte range from selection
        # This is simplified - actual implementation would parse the hex display

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selection",
            "selection.bin",
            "Binary Files (*.bin);;All Files (*.*)"
        )

        if file_path:
            # Export selected bytes
            pass  # Implementation needed

    def clear_highlights(self):
        """Clear all highlighting"""
        self.highlighted_regions.clear()
        self.selection_info.clear()
        self.update_display()

    def _clear_structure_view(self):
        """Clear structure view when no PE analysis available"""
        self.structure_tree.setModel(None)
        self.structure_model = None
        self.file_model = None
        self.structure_info_text.clear()

        # Disable RVA controls
        self.rva_spin.setEnabled(False)
        self.goto_rva_btn.setEnabled(False)

    def _on_structure_visibility_changed(self, visible: bool):
        """Handle structure tree visibility toggle"""
        self.structure_tree.setVisible(visible)

    def _expand_all_structures(self):
        """Expand all items in structure tree"""
        if self.structure_tree.model():
            self.structure_tree.expandAll()

    def _collapse_all_structures(self):
        """Collapse all items in structure tree"""
        if self.structure_tree.model():
            self.structure_tree.collapseAll()

    def _on_structure_clicked(self, index: QModelIndex):
        """Handle single click on structure tree item"""
        if not self.structure_model:
            return

        # Get offset and size for the clicked item
        offset, size = self.structure_model.get_item_offset_and_size(index)

        # Update structure info
        self._update_structure_info(index)

        # Highlight in hex view if valid offset
        if offset is not None and size is not None:
            # Add temporary highlight for clicked structure
            self.highlighted_regions = [
                region for region in self.highlighted_regions
                if not hasattr(region, '_temporary')
            ]

            # Add new temporary highlight
            highlight_color = QColor(100, 200, 255, 80)  # Light blue
            temp_region = (offset, offset + size, highlight_color)
            temp_region._temporary = True
            self.highlighted_regions.append(temp_region)

            self.apply_highlighting()

    def _on_structure_double_clicked(self, index: QModelIndex):
        """Handle double click on structure tree item - navigate to location"""
        if not self.structure_model:
            return

        # Get offset and size for the clicked item
        offset, size = self.structure_model.get_item_offset_and_size(index)

        if offset is not None:
            # Navigate to the structure location
            self.go_to_offset(offset)

            # Emit signal for external listeners
            self.offset_selected.emit(offset)

            # Also check for RVA navigation
            rva = self.structure_model.get_item_rva(index)
            if rva is not None:
                self.rva_selected.emit(rva)

    def _on_structure_navigation(self, offset: int, size: int):
        """Handle navigation signal from structure model"""
        self.go_to_offset(offset)

        # Add highlight for the structure
        highlight_color = QColor(255, 200, 100, 100)  # Light orange
        self.highlighted_regions.append((offset, offset + size, highlight_color))
        self.apply_highlighting()

    def _on_rva_navigation(self, rva: int):
        """Handle RVA navigation signal from structure model"""
        self.go_to_rva(rva)

    def _update_structure_info(self, index: QModelIndex):
        """Update structure info display"""
        if not self.structure_model:
            return

        self.structure_info_text.clear()

        item = index.internalPointer()
        if not item:
            return

        # Get basic info
        name = self.structure_model.data(index, Qt.DisplayRole)
        self.structure_info_text.append(f"Selected: {name}")

        # Get offset and size
        offset, size = self.structure_model.get_item_offset_and_size(index)
        if offset is not None:
            self.structure_info_text.append(f"File Offset: 0x{offset:X}")

        if size is not None:
            self.structure_info_text.append(f"Size: 0x{size:X} ({size} bytes)")

        # Get RVA if available
        rva = self.structure_model.get_item_rva(index)
        if rva is not None:
            self.structure_info_text.append(f"RVA: 0x{rva:X}")

        # Add tooltip info if available
        tooltip = self.structure_model.data(index, Qt.ToolTipRole)
        if tooltip and tooltip != name:
            self.structure_info_text.append(f"\nDetails:\n{tooltip}")
