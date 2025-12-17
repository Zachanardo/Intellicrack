"""Hex Viewer Widget for Protection Analysis.

Provides hex view capabilities integrated with the Intellicrack Protection Engine.
Supports navigation, search, and highlighting of important binary regions.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QBrush,
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QModelIndex,
    QPoint,
    QPushButton,
    QSpinBox,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTextCharFormat,
    QTextCursor,
    QTextEdit,
    QThread,
    QTreeView,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
    pyqtSlot,
)

from ...utils.logger import get_logger
from .pe_file_model import PEFileModel, create_file_model
from .pe_structure_model import PEStructureModel


logger = get_logger(__name__)


class HexViewerThread(QThread):
    """Thread for loading large binary files."""

    data_loaded = pyqtSignal(bytes)
    progress_update = pyqtSignal(int)
    error_occurred = pyqtSignal(str)

    def __init__(self, file_path: str, offset: int = 0, size: int | None = None) -> None:
        """Initialize hex viewer thread with file path, offset, and optional size parameters."""
        super().__init__()
        self.file_path = file_path
        self.offset = offset
        self.size = size

    def run(self) -> None:
        """Load file data in background thread."""
        try:
            file_size = os.path.getsize(self.file_path)

            # Limit size to prevent memory issues
            max_size = 10 * 1024 * 1024  # 10MB max
            if self.size is None or self.size > max_size:
                self.size = min(file_size - self.offset, max_size)

            with open(self.file_path, "rb") as f:
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
    """Hex viewer widget with protection analysis integration."""

    # Signals
    #: Offset clicked (type: int)
    offset_selected = pyqtSignal(int)
    #: Start, end offsets (type: int, int)
    region_highlighted = pyqtSignal(int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize hex viewer widget with file data, PE analysis components, and UI setup."""
        super().__init__(parent)
        self.file_path: str | None = None
        self.file_data: bytes | None = None
        self.current_offset = 0
        self.bytes_per_line = 16
        self.highlighted_regions: list[tuple[int, int, QColor]] = []

        # PE analysis components
        self.file_model: PEFileModel | None = None
        self.structure_model: PEStructureModel | None = None

        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
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

        # Add context menu to hex display for string extraction
        self.hex_display.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hex_display.customContextMenuRequested.connect(self._show_context_menu)

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
        """Create control bar with navigation and search."""
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
        self.search_input.setToolTip("Enter search pattern in selected format (Hex, ASCII, or Unicode)")
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
        """Create PE structure tree panel."""
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
        """Create information panel."""
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

    def load_file(self, file_path: str, offset: int = 0, size: int | None = None) -> None:
        """Load a binary file with PE analysis."""
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

                logger.info("PE analysis successful for %s", file_path)
            else:
                # Not a PE file or analysis failed
                self._clear_structure_view()
                logger.info("File %s is not a supported format for structure analysis", file_path)

        except Exception as e:
            logger.warning("PE analysis failed for %s: %s", file_path, e, exc_info=True)
            self._clear_structure_view()

        # Start loading thread
        self.load_thread = HexViewerThread(file_path, offset, size)
        self.load_thread.data_loaded.connect(self.on_data_loaded)
        self.load_thread.progress_update.connect(self.on_load_progress)
        self.load_thread.error_occurred.connect(self.on_load_error)
        self.load_thread.start()

    @pyqtSlot(bytes)
    def on_data_loaded(self, data: bytes) -> None:
        """Handle loaded data."""
        self.file_data = data

        # Update offset spinner range
        if self.file_path:
            file_size = os.path.getsize(self.file_path)
            self.offset_spin.setMaximum(file_size - 1)

        # Update display
        self.update_display()

        # Update status
        self.status_label.setText(
            f"Loaded: {os.path.basename(self.file_path)} ({len(data):,} bytes from offset 0x{self.current_offset:X})",
        )

    @pyqtSlot(int)
    def on_load_progress(self, progress: int) -> None:
        """Handle load progress."""
        self.status_label.setText(
            f"Loading {os.path.basename(self.file_path)}... {progress}%",
        )

    @pyqtSlot(str)
    def on_load_error(self, error: str) -> None:
        """Handle load error."""
        QMessageBox.critical(self, "Load Error", f"Error loading file: {error}")
        self.status_label.setText("Load failed")

    def update_display(self) -> None:
        """Update hex and ASCII displays."""
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
                hex_line += " ".join(hex_values[k : k + 4]) + "  "

            hex_lines.append(hex_line.rstrip())
            ascii_lines.append("".join(ascii_values))

        # Set text
        self.hex_display.setPlainText("\n".join(hex_lines))
        self.ascii_display.setPlainText("\n".join(ascii_lines))

        # Apply highlighting
        self.apply_highlighting()

    def apply_highlighting(self) -> None:
        """Apply highlighting to regions."""
        for start, end, color in self.highlighted_regions:
            self.highlight_region(start, end, color)

    def highlight_region(self, start: int, end: int, color: QColor) -> None:
        """Highlight a region in the hex view."""
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

        # Highlight bytes in the range
        self.bytes_per_line * 3
        for line_idx in range(start_line, min(end_line + 1, len(self.file_data) // self.bytes_per_line + 1)):
            cursor.movePosition(QTextCursor.StartOfBlock)

            if line_idx == start_line:
                byte_in_line = (start - self.current_offset) % self.bytes_per_line
                char_offset = 10 + byte_in_line * 3
            else:
                char_offset = 10

            for _ in range(char_offset):
                cursor.movePosition(QTextCursor.Right)

            if line_idx == end_line:
                bytes_to_highlight = (end - self.current_offset) % self.bytes_per_line + 1
            else:
                bytes_to_highlight = self.bytes_per_line - (byte_in_line if line_idx == start_line else 0)

            for _ in range(bytes_to_highlight * 3):
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)

            if cursor.hasSelection():
                cursor.setCharFormat(fmt)

            if line_idx < end_line:
                cursor.movePosition(QTextCursor.Down)

    def go_to_offset(self, offset: int) -> None:
        """Navigate to specific offset."""
        if self.file_path and 0 <= offset < os.path.getsize(self.file_path):
            self.load_file(self.file_path, offset)
            self.offset_selected.emit(offset)

    def go_to_rva(self, rva: int) -> None:
        """Navigate to specific RVA."""
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

            if section := self.file_model.get_section_at_rva(rva):
                self.structure_info_text.append(f"Section: {section.name}")
                self.structure_info_text.append(f"Section Offset: 0x{rva - section.virtual_address:X}")
        else:
            QMessageBox.warning(self, "Invalid RVA", f"RVA 0x{rva:X} is not valid for this file")

    def search_data(self) -> None:
        """Search for pattern in data."""
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
                pattern_bytes = pattern.encode("ascii")
            else:  # Unicode
                pattern_bytes = pattern.encode("utf-16le")

            # Search for pattern
            index = self.file_data.find(pattern_bytes)
            if index != -1:
                # Found - navigate to offset
                found_offset = self.current_offset + index
                self.go_to_offset(found_offset)

                # Highlight found data
                self.highlighted_regions.append(
                    (found_offset, found_offset + len(pattern_bytes), QColor(255, 255, 0, 100)),
                )
                self.update_display()

                QMessageBox.information(
                    self,
                    "Search Result",
                    f"Pattern found at offset 0x{found_offset:X}",
                )
            else:
                QMessageBox.information(
                    self,
                    "Search Result",
                    "Pattern not found in current view",
                )

        except Exception as e:
            logger.error("Exception in hex_viewer_widget: %s", e)
            QMessageBox.warning(
                self,
                "Search Error",
                f"Invalid search pattern: {e!s}",
            )

    def add_protection_highlight(self, offset: int, size: int, protection_name: str) -> None:
        """Add highlighting for detected protection region."""
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

    def interpret_data_at_cursor(self) -> None:
        """Interpret data at current cursor position."""
        cursor = self.hex_display.textCursor()
        position = cursor.position()

        logger.debug("Cursor position: %d", position)

        # Calculate byte offset from cursor position
        # This is complex due to formatting - simplified version
        line = cursor.blockNumber()
        byte_offset = line * self.bytes_per_line

        if byte_offset < len(self.file_data):
            self.interpret_bytes(byte_offset)

    def interpret_bytes(self, offset: int) -> None:
        """Interpret bytes at offset as various data types."""
        if not self.file_data or offset >= len(self.file_data):
            return

        self.interpreter_table.setRowCount(0)

        # Get available bytes
        available = len(self.file_data) - offset

        interpretations = []

        # 8-bit values
        if available >= 1:
            byte_val = self.file_data[offset]
            interpretations.extend((
                ("UInt8", str(byte_val)),
                ("Int8", str(struct.unpack("b", bytes([byte_val]))[0])),
                (
                    "Char",
                    repr(chr(byte_val)) if 32 <= byte_val <= 126 else "N/A",
                ),
            ))
        # 16-bit values
        if available >= 2:
            data = self.file_data[offset : offset + 2]
            interpretations.extend((
                ("UInt16 LE", str(struct.unpack("<H", data)[0])),
                ("UInt16 BE", str(struct.unpack(">H", data)[0])),
                ("Int16 LE", str(struct.unpack("<h", data)[0])),
                ("Int16 BE", str(struct.unpack(">h", data)[0])),
            ))
        # 32-bit values
        if available >= 4:
            data = self.file_data[offset : offset + 4]
            interpretations.append(("UInt32 LE", str(struct.unpack("<I", data)[0])))
            interpretations.append(("UInt32 BE", str(struct.unpack(">I", data)[0])))
            interpretations.append(("Int32 LE", str(struct.unpack("<i", data)[0])))
            interpretations.append(("Int32 BE", str(struct.unpack(">i", data)[0])))
            interpretations.append(("Float LE", f"{struct.unpack('<f', data)[0]:.6f}"))
            interpretations.append(("Float BE", f"{struct.unpack('>f', data)[0]:.6f}"))

        # 64-bit values
        if available >= 8:
            data = self.file_data[offset : offset + 8]
            interpretations.append(("UInt64 LE", str(struct.unpack("<Q", data)[0])))
            interpretations.append(("UInt64 BE", str(struct.unpack(">Q", data)[0])))
            interpretations.append(("Int64 LE", str(struct.unpack("<q", data)[0])))
            interpretations.append(("Int64 BE", str(struct.unpack(">q", data)[0])))
            interpretations.append(("Double LE", f"{struct.unpack('<d', data)[0]:.10f}"))
            interpretations.append(("Double BE", f"{struct.unpack('>d', data)[0]:.10f}"))

        # Add to table
        for data_type, value in interpretations:
            row = self.interpreter_table.rowCount()
            self.interpreter_table.insertRow(row)
            self.interpreter_table.setItem(row, 0, QTableWidgetItem(data_type))
            self.interpreter_table.setItem(row, 1, QTableWidgetItem(value))

    def export_selection(self) -> None:
        """Export selected bytes to file."""
        # Get selection from hex display
        cursor = self.hex_display.textCursor()
        if not cursor.hasSelection():
            QMessageBox.information(self, "No Selection", "Please select bytes to export")
            return

        # Get selected text
        selected_text = cursor.selectedText()

        # Parse hex values from selected text
        try:
            hex_bytes = []
            lines = selected_text.split("\n")

            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue

                # Find the colon that separates offset from hex data
                colon_pos = line.find(":")
                hex_part = line if colon_pos == -1 else line[colon_pos + 1 :]
                # Remove all spaces and extract hex pairs
                hex_part = hex_part.replace(" ", "")

                # Process hex pairs (2 characters at a time)
                for i in range(0, len(hex_part), 2):
                    if i + 1 < len(hex_part):
                        hex_pair = hex_part[i : i + 2]
                        # Validate hex characters
                        if all(c in "0123456789ABCDEFabcdef" for c in hex_pair):
                            hex_bytes.append(hex_pair)

            if not hex_bytes:
                QMessageBox.warning(self, "No Valid Data", "No valid hex data found in selection")
                return

            # Convert hex strings to bytes
            binary_data = bytes.fromhex("".join(hex_bytes))

            # Get save file path
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Selection",
                "selection.bin",
                "Binary Files (*.bin);;All Files (*.*)",
            )

            if file_path:
                # Write bytes to file
                with open(file_path, "wb") as f:
                    f.write(binary_data)

                # Show success message
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Exported {len(binary_data)} bytes to:\n{file_path}",
                )

                # Log the export
                logger.info("Exported %s bytes to %s", len(binary_data), file_path)

        except ValueError as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Invalid hex data: {e!s}",
            )
        except OSError as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to write file: {e!s}",
            )
        except Exception as e:
            logger.error("Export error: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "Export Error",
                f"Unexpected error: {e!s}",
            )

    def clear_highlights(self) -> None:
        """Clear all highlighting."""
        self.highlighted_regions.clear()
        self.selection_info.clear()
        self.update_display()

    def _clear_structure_view(self) -> None:
        """Clear structure view when no PE analysis available."""
        self.structure_tree.setModel(None)
        self.structure_model = None
        self.file_model = None
        self.structure_info_text.clear()

        # Disable RVA controls
        self.rva_spin.setEnabled(False)
        self.goto_rva_btn.setEnabled(False)

    def _on_structure_visibility_changed(self, visible: bool) -> None:
        """Handle structure tree visibility toggle."""
        self.structure_tree.setVisible(visible)

    def _expand_all_structures(self) -> None:
        """Expand all items in structure tree."""
        if self.structure_tree.model():
            self.structure_tree.expandAll()

    def _collapse_all_structures(self) -> None:
        """Collapse all items in structure tree."""
        if self.structure_tree.model():
            self.structure_tree.collapseAll()

    def _on_structure_clicked(self, index: QModelIndex) -> None:
        """Handle single click on structure tree item."""
        if not self.structure_model:
            return

        # Get offset and size for the clicked item
        offset, size = self.structure_model.get_item_offset_and_size(index)

        # Update structure info
        self._update_structure_info(index)

        # Highlight in hex view if valid offset
        if offset is not None and size is not None:
            # Add temporary highlight for clicked structure
            self.highlighted_regions = [region for region in self.highlighted_regions if not hasattr(region, "_temporary")]

            # Add new temporary highlight
            highlight_color = QColor(100, 200, 255, 80)  # Light blue
            temp_region = (offset, offset + size, highlight_color)
            temp_region._temporary = True
            self.highlighted_regions.append(temp_region)

            self.apply_highlighting()

    def _on_structure_double_clicked(self, index: QModelIndex) -> None:
        """Handle double click on structure tree item - navigate to location."""
        if not self.structure_model:
            return

        # Get offset and size for the clicked item
        offset, _size = self.structure_model.get_item_offset_and_size(index)

        if offset is not None:
            # Navigate to the structure location
            self.go_to_offset(offset)

            # Emit signal for external listeners
            self.offset_selected.emit(offset)

            # Also check for RVA navigation
            rva = self.structure_model.get_item_rva(index)
            if rva is not None:
                self.rva_selected.emit(rva)

    def _on_structure_navigation(self, offset: int, size: int) -> None:
        """Handle navigation signal from structure model."""
        self.go_to_offset(offset)

        # Add highlight for the structure
        highlight_color = QColor(255, 200, 100, 100)  # Light orange
        self.highlighted_regions.append((offset, offset + size, highlight_color))
        self.apply_highlighting()

    def _on_rva_navigation(self, rva: int) -> None:
        """Handle RVA navigation signal from structure model."""
        self.go_to_rva(rva)

    def _update_structure_info(self, index: QModelIndex) -> None:
        """Update structure info display."""
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

    def _show_context_menu(self, position: QPoint) -> None:
        """Show context menu for hex display."""
        from intellicrack.handlers.pyqt6_handler import QAction, QMenu

        menu = QMenu(self)

        # Extract strings action
        extract_strings_action = QAction("Extract Strings", self)
        extract_strings_action.triggered.connect(self._extract_strings_from_selection)
        menu.addAction(extract_strings_action)

        # Extract wide strings action
        extract_wide_strings_action = QAction("Extract Wide Strings (Unicode)", self)
        extract_wide_strings_action.triggered.connect(lambda: self._extract_strings_from_selection(wide=True))
        menu.addAction(extract_wide_strings_action)

        menu.addSeparator()

        # Extract all strings from file
        extract_all_strings_action = QAction("Extract All Strings from File", self)
        extract_all_strings_action.triggered.connect(self._extract_all_strings)
        menu.addAction(extract_all_strings_action)

        # Find license patterns
        find_license_action = QAction("Find License Patterns", self)
        find_license_action.triggered.connect(self._find_license_patterns)
        menu.addAction(find_license_action)

        menu.addSeparator()

        # Copy selection
        copy_hex_action = QAction("Copy Hex", self)
        copy_hex_action.triggered.connect(self._copy_hex_selection)
        menu.addAction(copy_hex_action)

        copy_ascii_action = QAction("Copy ASCII", self)
        copy_ascii_action.triggered.connect(self._copy_ascii_selection)
        menu.addAction(copy_ascii_action)

        menu.exec(self.hex_display.mapToGlobal(position))

    def _extract_strings_from_selection(self, wide: bool = False) -> None:
        """Extract strings from selected hex data."""
        try:
            from PyQt6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QSpinBox, QTextEdit, QVBoxLayout

            from intellicrack.core.analysis.memory_forensics_engine import MemoryForensicsEngine

            # Get selected data
            cursor = self.hex_display.textCursor()
            selected_text = cursor.selectedText()

            if not selected_text and self.file_data:
                # Use entire loaded data if no selection
                data_to_analyze = self.file_data
            elif selected_text:
                # Convert hex text to bytes
                hex_only = "".join(selected_text.split())
                hex_only = "".join(c for c in hex_only if c in "0123456789ABCDEFabcdef")
                try:
                    data_to_analyze = bytes.fromhex(hex_only)
                except ValueError:
                    QMessageBox.warning(self, "Invalid Selection", "Please select valid hex data")
                    return
            else:
                QMessageBox.information(self, "No Data", "No data loaded or selected")
                return

            # Create results dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("String Extraction Results")
            dialog.setGeometry(100, 100, 800, 600)

            layout = QVBoxLayout()

            # Options
            options_layout = QHBoxLayout()

            min_length_label = QLabel("Minimum Length:")
            min_length_spin = QSpinBox()
            min_length_spin.setMinimum(3)
            min_length_spin.setMaximum(100)
            min_length_spin.setValue(5)

            options_layout.addWidget(min_length_label)
            options_layout.addWidget(min_length_spin)

            filter_check = QCheckBox("Filter License-Related Only")
            options_layout.addWidget(filter_check)

            refresh_btn = QPushButton("Refresh")
            options_layout.addWidget(refresh_btn)

            options_layout.addStretch()
            layout.addLayout(options_layout)

            # Results display
            results_text = QTextEdit()
            results_text.setReadOnly(True)
            results_text.setFont(QFont("Consolas", 10))
            layout.addWidget(results_text)

            # Statistics
            stats_label = QLabel("Extracting strings...")
            layout.addWidget(stats_label)

            # Buttons
            button_layout = QHBoxLayout()

            export_btn = QPushButton("Export")
            copy_btn = QPushButton("Copy All")
            close_btn = QPushButton("Close")

            button_layout.addWidget(export_btn)
            button_layout.addWidget(copy_btn)
            button_layout.addStretch()
            button_layout.addWidget(close_btn)

            layout.addLayout(button_layout)

            def extract_and_display() -> None:
                """Extract strings and display results."""
                min_length = min_length_spin.value()
                filter_license = filter_check.isChecked()

                if wide:
                    # Extract Unicode strings
                    strings = self._extract_unicode_strings(data_to_analyze, min_length)
                else:
                    # Use MemoryForensicsEngine for ASCII extraction
                    engine = MemoryForensicsEngine()
                    strings = engine.extract_strings(data_to_analyze, min_length)

                # Filter for license-related if requested
                if filter_license:
                    license_keywords = [
                        "license",
                        "activation",
                        "serial",
                        "key",
                        "product",
                        "registration",
                        "trial",
                        "expire",
                        "valid",
                        "crack",
                        "patch",
                        "keygen",
                        "hwid",
                        "machine",
                        "signature",
                    ]
                    filtered = []
                    for s in strings:
                        s_lower = s.lower()
                        if any(keyword in s_lower for keyword in license_keywords):
                            filtered.append(s)
                    strings = filtered

                # Display results
                results = []
                results.append(f"{'=' * 60}")
                results.append(f"String Extraction Results ({'Unicode' if wide else 'ASCII'})")
                results.append(f"{'=' * 60}")
                results.append(f"Data size: {len(data_to_analyze):,} bytes")
                results.append(f"Minimum length: {min_length} characters")
                results.append(f"Strings found: {len(strings)}")
                if filter_license:
                    results.append("Filter: License-related only")
                results.append(f"{'=' * 60}\n")

                # Group strings by potential category
                categories = {
                    "URLs": [],
                    "Paths": [],
                    "License": [],
                    "Registry": [],
                    "Error Messages": [],
                    "Other": [],
                }

                for string in strings:
                    if string.startswith("http://") or string.startswith("https://"):
                        categories["URLs"].append(string)
                    elif "\\" in string or "/" in string:
                        if any(ext in string.lower() for ext in [".exe", ".dll", ".sys", ".dat"]):
                            categories["Paths"].append(string)
                        elif "HKEY" in string or "Software\\" in string:
                            categories["Registry"].append(string)
                        else:
                            categories["Other"].append(string)
                    elif any(word in string.lower() for word in ["license", "serial", "activation", "key"]):
                        categories["License"].append(string)
                    elif any(word in string.lower() for word in ["error", "fail", "invalid", "exception"]):
                        categories["Error Messages"].append(string)
                    else:
                        categories["Other"].append(string)

                # Display by category
                for category, items in categories.items():
                    if items:
                        results.append(f"\n[{category}] ({len(items)} strings)")
                        results.append("-" * 40)
                        results.extend(items[:100])  # Limit display
                        if len(items) > 100:
                            results.append(f"... and {len(items) - 100} more")

                results_text.setPlainText("\n".join(results))
                stats_label.setText(f"Total: {len(strings)} strings | Displayed: {min(len(strings), 600)} strings")

            def export_strings() -> None:
                """Export strings to file."""
                file_path, _ = QFileDialog.getSaveFileName(
                    dialog,
                    "Export Strings",
                    "extracted_strings.txt",
                    "Text Files (*.txt);;All Files (*)",
                )

                if file_path:
                    try:
                        with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
                            f.write(results_text.toPlainText())
                        QMessageBox.information(dialog, "Export Complete", f"Strings exported to {file_path}")
                    except Exception as e:
                        QMessageBox.critical(dialog, "Export Error", f"Failed to export: {e!s}")

            def copy_all() -> None:
                """Copy all results to clipboard."""
                clipboard = QApplication.clipboard()
                clipboard.setText(results_text.toPlainText())
                stats_label.setText("Results copied to clipboard")

            # Connect signals
            refresh_btn.clicked.connect(extract_and_display)
            export_btn.clicked.connect(export_strings)
            copy_btn.clicked.connect(copy_all)
            close_btn.clicked.connect(dialog.close)

            # Initial extraction
            extract_and_display()

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            logger.error("String extraction failed: %s", e, exc_info=True)
            QMessageBox.critical(self, "Extraction Error", f"Failed to extract strings: {e!s}")

    def _extract_unicode_strings(self, data: bytes, min_length: int = 5) -> list[str]:
        """Extract Unicode (UTF-16) strings from binary data."""
        strings = []
        current_string = ""

        # Process as UTF-16 LE (Windows default)
        i = 0
        while i < len(data) - 1:
            # Check for printable Unicode character
            char_bytes = data[i : i + 2]
            if char_bytes[1] == 0 and 32 <= char_bytes[0] <= 126:  # Printable ASCII
                current_string += chr(char_bytes[0])
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
            i += 2

        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)

        return strings

    def _extract_all_strings(self) -> None:
        """Extract all strings from the entire file."""
        if not self.file_path:
            QMessageBox.information(self, "No File", "Please load a file first")
            return

        try:
            # Read entire file
            with open(self.file_path, "rb") as f:
                data = f.read()

            # Use a copy of file_data temporarily
            original_data = self.file_data
            self.file_data = data

            # Extract strings
            self._extract_strings_from_selection()

            # Restore original data
            self.file_data = original_data

        except Exception as e:
            logger.error("Failed to read file for string extraction: %s", e, exc_info=True)
            QMessageBox.critical(self, "Read Error", f"Failed to read file: {e!s}")

    def _find_license_patterns(self) -> None:
        """Find and highlight license-related patterns in the hex view."""
        try:
            import re

            from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QListWidget, QPushButton, QVBoxLayout

            if not self.file_data:
                QMessageBox.information(self, "No Data", "Please load a file first")
                return

            # License-related patterns to search for
            patterns = [
                (b"LICENSE", "License keyword"),
                (b"ACTIVATION", "Activation keyword"),
                (b"SERIAL", "Serial keyword"),
                (b"PRODUCT.?KEY", "Product key pattern"),
                (b"TRIAL", "Trial keyword"),
                (b"EXPIRE", "Expiration keyword"),
                (b"HWID", "Hardware ID"),
                (b"MACHINE.?ID", "Machine ID pattern"),
                (b"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}", "Serial number pattern"),
                (b"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "UUID pattern"),
            ]

            # Create results dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("License Pattern Search Results")
            dialog.setGeometry(100, 100, 600, 400)

            layout = QVBoxLayout()

            info_label = QLabel("Found license-related patterns:")
            layout.addWidget(info_label)

            results_list = QListWidget()
            layout.addWidget(results_list)

            # Search for patterns
            found_count = 0
            for pattern_bytes, description in patterns:
                try:
                    matches = list(re.finditer(pattern_bytes, self.file_data, re.IGNORECASE))
                    if matches:
                        found_count += len(matches)
                        for match in matches:
                            offset = match.start()
                            matched_text = match.group(0).decode("utf-8", errors="ignore")
                            item_text = f"0x{offset:08X}: {description} - '{matched_text}'"
                            results_list.addItem(item_text)
                except (struct.error, ValueError, TypeError) as e:
                    logger.debug("Failed to parse signature match: %s", e)

            info_label.setText(f"Found {found_count} license-related patterns:")

            # Buttons
            button_layout = QHBoxLayout()

            goto_btn = QPushButton("Go to Offset")
            close_btn = QPushButton("Close")

            button_layout.addWidget(goto_btn)
            button_layout.addStretch()
            button_layout.addWidget(close_btn)

            layout.addLayout(button_layout)

            def goto_selected() -> None:
                """Navigate to selected pattern offset."""
                current_item = results_list.currentItem()
                if current_item:
                    text = current_item.text()
                    # Extract offset from text
                    if text.startswith("0x"):
                        offset_str = text.split(":")[0]
                        offset = int(offset_str, 16)
                        self.go_to_offset(offset)
                        dialog.close()

            goto_btn.clicked.connect(goto_selected)
            results_list.itemDoubleClicked.connect(goto_selected)
            close_btn.clicked.connect(dialog.close)

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            logger.error("Pattern search failed: %s", e, exc_info=True)
            QMessageBox.critical(self, "Search Error", f"Failed to search patterns: {e!s}")

    def _copy_hex_selection(self) -> None:
        """Copy selected hex to clipboard."""
        cursor = self.hex_display.textCursor()
        if selected_text := cursor.selectedText():
            # Clean up hex for copying
            hex_only = "".join(c for c in selected_text if c in "0123456789ABCDEFabcdef ")
            clipboard = QApplication.clipboard()
            clipboard.setText(hex_only)

    def _copy_ascii_selection(self) -> None:
        """Copy ASCII representation to clipboard."""
        cursor = self.ascii_display.textCursor()
        if selected_text := cursor.selectedText():
            clipboard = QApplication.clipboard()
            clipboard.setText(selected_text)
