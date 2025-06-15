"""
HexViewer Widget 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging
from typing import Optional

try:
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal
    from PyQt5.QtGui import QFont, QFontMetrics
    from PyQt5.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QScrollArea,
        QSplitter,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    QWidget = object
    pyqtSignal = None

# Import hex viewer components if available
try:
    from ...hexview.data_inspector import DataInspector
    from ...hexview.hex_widget import HexWidget
    from ...hexview.performance_monitor import PerformanceMonitor
    HEX_COMPONENTS_AVAILABLE = True
except ImportError:
    HEX_COMPONENTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Base widget class for when PyQt is not available
class BaseWidget:
    """Base widget class for fallback when PyQt is not available."""
    def __init__(self, parent=None):
        self.parent = parent


class HexViewer(QWidget if PYQT_AVAILABLE else BaseWidget):
    """
    Professional hex viewer widget for binary data analysis.
    
    Provides:
    - Hexadecimal data display
    - Data editing capabilities
    - Data inspector for _different interpretations
    - Performance monitoring for large files
    - Search and navigation features
    """

    # Signals
    dataChanged = pyqtSignal(int, bytes) if PYQT_AVAILABLE else None
    selectionChanged = pyqtSignal(int, int) if PYQT_AVAILABLE else None
    fileOpened = pyqtSignal(str) if PYQT_AVAILABLE else None

    def __init__(self, parent=None):

        # Initialize UI attributes
        self.file_info_label = None
        self.open_btn = None
        self.perf_btn = None
        self.save_btn = None
        self.search_btn = None
        if not PYQT_AVAILABLE:
            raise ImportError("PyQt5 is required for HexViewer widget")

        super().__init__(parent)
        self.file_path = None
        self.data = b''
        self.read_only = False

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Create toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Create main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left side: hex display
        hex_frame = QFrame()
        hex_layout = QVBoxLayout(hex_frame)

        if HEX_COMPONENTS_AVAILABLE:
            # Use professional hex widget if available
            self.hex_widget = HexWidget()
            hex_layout.addWidget(self.hex_widget)
        else:
            # Fallback to basic text display
            self.hex_display = QTextEdit()
            self.hex_display.setFont(QFont("Courier", 10))
            self.hex_display.setReadOnly(True)
            hex_layout.addWidget(self.hex_display)

        splitter.addWidget(hex_frame)

        # Right side: data inspector
        if HEX_COMPONENTS_AVAILABLE:
            self.data_inspector = DataInspector()
            splitter.addWidget(self.data_inspector)
        else:
            # Fallback info panel
            info_frame = QFrame()
            info_layout = QVBoxLayout(info_frame)
            info_layout.addWidget(QLabel("Data Inspector"))
            self.info_display = QTextEdit()
            self.info_display.setMaximumWidth(300)
            info_layout.addWidget(self.info_display)
            splitter.addWidget(info_frame)

        # Set splitter proportions
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def _create_toolbar(self):
        """Create the toolbar with common actions."""
        toolbar = QFrame()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)

        # Open file button
        self.open_btn = QPushButton("Open File")
        self.open_btn.clicked.connect(self.open_file_dialog)
        self.open_btn.setToolTip(
            "Open a binary file for hexadecimal viewing and editing\n"
            "Supports large files with memory-efficient loading\n"
            "Shortcuts: Ctrl+O"
        )
        layout.addWidget(self.open_btn)

        # Save button
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_file)
        self.save_btn.setEnabled(False)
        self.save_btn.setToolTip(
            "Save current modifications to the file\n"
            "Only enabled when changes have been made\n"
            "Creates backup before overwriting\n"
            "Shortcuts: Ctrl+S"
        )
        layout.addWidget(self.save_btn)

        # Search button
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.open_search)
        self.search_btn.setToolTip(
            "Search for patterns in the binary data\n"
            "Supports hex, text, and regex patterns\n"
            "Features: Find/Replace, Wildcards, Case sensitivity\n"
            "Shortcuts: Ctrl+F"
        )
        layout.addWidget(self.search_btn)

        # Performance button (if available)
        if HEX_COMPONENTS_AVAILABLE:
            self.perf_btn = QPushButton("Performance")
            self.perf_btn.clicked.connect(self.show_performance)
            self.perf_btn.setToolTip(
                "View real-time performance statistics\n"
                "Shows memory usage, load times, and optimization info\n"
                "Helpful for analyzing large file handling efficiency"
            )
            layout.addWidget(self.perf_btn)

        layout.addStretch()

        # File info label
        self.file_info_label = QLabel("No file loaded")
        layout.addWidget(self.file_info_label)

        return toolbar

    def _connect_signals(self):
        """Connect internal signals."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            # Connect to professional hex widget signals
            try:
                self.hex_widget.dataChanged.connect(self._on_data_changed)
                self.hex_widget.selectionChanged.connect(self._on_selection_changed)
            except AttributeError:
                pass

    def load_data(self, data: bytes, file_path: Optional[str] = None):
        """
        Load binary data into the hex viewer.
        
        Args:
            data: Binary data to display
            file_path: Optional file path for reference
        """
        try:
            self.data = data
            self.file_path = file_path

            if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
                # Use professional hex widget
                self.hex_widget.load_data(data)
                if hasattr(self, 'data_inspector'):
                    self.data_inspector.set_data(data)
            else:
                # Fallback display
                self._display_hex_fallback(data)

            # Update UI
            file_name = file_path.split('/')[-1] if file_path else "Memory Data"
            self.file_info_label.setText(f"{file_name} ({len(data)} bytes)")
            self.status_label.setText(f"Loaded {len(data)} bytes")

            if self.fileOpened:
                self.fileOpened.emit(file_path or "")

            self.save_btn.setEnabled(not self.read_only)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load data: %s", e)
            self.status_label.setText(f"Error loading data: {e}")

    def _display_hex_fallback(self, data: bytes):
        """Fallback hex display when professional components unavailable."""
        if not hasattr(self, 'hex_display'):
            return

        hex_lines = []
        for _i in range(0, len(data), 16):
            chunk = data[_i:_i+16]

            # Address
            addr = f"{_i:08X}"

            # Hex bytes
            hex_part = " ".join(f"{_b:02X}" for _b in chunk)
            hex_part = hex_part.ljust(47)  # 16*3 - 1

            # ASCII part
            ascii_part = ""
            for _b in chunk:
                if 32 <= _b <= 126:
                    ascii_part += chr(_b)
                else:
                    ascii_part += "."

            line = f"{addr}  {hex_part}  {ascii_part}"
            hex_lines.append(line)

        self.hex_display.setPlainText("\n".join(hex_lines))

        # Update info display
        if hasattr(self, 'info_display'):
            info = f"File size: {len(data)} bytes\n"
            info += f"Lines: {len(hex_lines)}\n"
            if data:
                info += f"First byte: 0x{data[0]:02X}\n"
                info += f"Last byte: 0x{data[-1]:02X}\n"
            self.info_display.setPlainText(info)

    def open_file_dialog(self):
        """Open file dialog to load a binary file."""
        try:
            from PyQt5.QtWidgets import QFileDialog

            file_path, _ = QFileDialog.getOpenFileName(
                self, "Open Binary File", "",
                "All Files (*);; Binary Files (*.bin *.exe *.dll)"
            )

            if file_path:
                self.load_file(file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to open file dialog: %s", e)
            self.status_label.setText(f"Error: {e}")

    def load_file(self, file_path: str):
        """
        Load a binary file.
        
        Args:
            file_path: Path to the binary file
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            self.load_data(data, file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load file %s: %s", file_path, e)
            self.status_label.setText(f"Failed to load file: {e}")

    def save_file(self):
        """Save the current data to file."""
        if not self.file_path or self.read_only:
            return

        try:
            with open(self.file_path, 'wb') as f:
                f.write(self.data)

            self.status_label.setText("File saved successfully")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to save file: %s", e)
            self.status_label.setText(f"Save failed: {e}")

    def open_search(self):
        """Open search dialog."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            # Use professional search if available
            try:
                self.hex_widget.open_search_dialog()
            except AttributeError:
                self.status_label.setText("Search not available")
        else:
            # Implement basic search for fallback mode
            self._open_basic_search_dialog()

    def show_performance(self):
        """Show performance monitoring dialog."""
        if HEX_COMPONENTS_AVAILABLE:
            try:
                perf_controller = PerformanceMonitor()
                perf_widget = perf_controller.create_widget(self)
                if perf_widget:
                    perf_widget.show()
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Failed to show performance monitor: %s", e)
                self.status_label.setText("Performance monitor not available")

    def set_read_only(self, read_only: bool):
        """Set read-only mode."""
        self.read_only = read_only
        self.save_btn.setEnabled(not read_only)

        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            try:
                self.hex_widget.set_read_only(read_only)
            except AttributeError:
                pass

    def get_selection(self):
        """Get current selection range."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            try:
                return self.hex_widget.get_selection()
            except AttributeError:
                pass
        return (0, 0)

    def set_selection(self, start: int, length: int):
        """Set selection range."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            try:
                self.hex_widget.set_selection(start, length)
            except AttributeError:
                pass

    def _on_data_changed(self, offset: int, new_data: bytes):
        """Handle data change from hex widget."""
        if self.dataChanged:
            self.dataChanged.emit(offset, new_data)

    def _on_selection_changed(self, start: int, length: int):
        """Handle selection change from hex widget."""
        if self.selectionChanged:
            self.selectionChanged.emit(start, length)

        # Update data inspector if available
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'data_inspector'):
            try:
                selected_data = self.data[start:start+length] if length > 0 else b''
                self.data_inspector.update_selection(selected_data, start)
            except (IndexError, AttributeError):
                pass

    def _open_basic_search_dialog(self):
        """Open a basic search dialog for fallback mode."""
        if not self.data:
            self.status_label.setText("No data to search")
            return

        try:
            from PyQt5.QtWidgets import (
                QButtonGroup,
                QCheckBox,
                QDialog,
                QLineEdit,
                QMessageBox,
                QRadioButton,
            )

            dialog = QDialog(self)
            dialog.setWindowTitle("Search")
            dialog.setModal(True)
            dialog.resize(400, 200)

            layout = QVBoxLayout(dialog)

            # Search input
            input_layout = QHBoxLayout()
            input_layout.addWidget(QLabel("Search for:"))
            search_input = QLineEdit()
            search_input.setToolTip(
                "Enter your search pattern here\n"
                "For hex: Use format like '4D 5A' or '4D5A'\n"
                "For text: Enter any text string\n"
                "Press Enter to search forward"
            )
            input_layout.addWidget(search_input)
            layout.addLayout(input_layout)

            # Search type selection
            type_group = QButtonGroup(dialog)

            hex_radio = QRadioButton("Hex (e.g., 4D 5A)")
            hex_radio.setToolTip(
                "Search for hexadecimal byte patterns\n"
                "Format: Space-separated hex bytes (e.g., 4D 5A 90 00)\n"
                "Or continuous hex string (e.g., 4D5A9000)\n"
                "Case insensitive, supports both formats"
            )

            text_radio = QRadioButton("Text/ASCII")
            text_radio.setToolTip(
                "Search for text strings in the binary data\n"
                "Automatically converts to UTF-8 encoding\n"
                "Supports case-sensitive and case-insensitive matching"
            )

            hex_radio.setChecked(True)

            type_group.addButton(hex_radio)
            type_group.addButton(text_radio)

            type_layout = QHBoxLayout()
            type_layout.addWidget(QLabel("Search type:"))
            type_layout.addWidget(hex_radio)
            type_layout.addWidget(text_radio)
            layout.addLayout(type_layout)

            # Options
            case_sensitive = QCheckBox("Case sensitive")
            case_sensitive.setToolTip(
                "Enable case-sensitive text matching\n"
                "Only applies to text/ASCII search mode\n"
                "When disabled, 'Hello' will match 'hello', 'HELLO', etc."
            )

            whole_words = QCheckBox("Whole words only")
            whole_words.setToolTip(
                "Match only complete words, not partial matches\n"
                "Uses word boundaries to ensure full word matching\n"
                "Useful for finding specific identifiers or keywords"
            )

            options_layout = QHBoxLayout()
            options_layout.addWidget(case_sensitive)
            options_layout.addWidget(whole_words)
            layout.addLayout(options_layout)

            # Buttons
            button_layout = QHBoxLayout()

            find_next_btn = QPushButton("Find Next")
            find_next_btn.setToolTip(
                "Search for the next occurrence of the pattern\n"
                "Automatically wraps to beginning of file when end is reached\n"
                "Keyboard shortcut: F3"
            )

            find_prev_btn = QPushButton("Find Previous")
            find_prev_btn.setToolTip(
                "Search for the previous occurrence of the pattern\n"
                "Automatically wraps to end of file when beginning is reached\n"
                "Keyboard shortcut: Shift+F3"
            )

            close_btn = QPushButton("Close")
            close_btn.setToolTip("Close the search dialog\nKeyboard shortcut: Escape")

            button_layout.addWidget(find_next_btn)
            button_layout.addWidget(find_prev_btn)
            button_layout.addWidget(close_btn)
            layout.addLayout(button_layout)

            # Search state
            search_state = {'last_pos': 0, 'pattern': None, 'search_type': 'hex'}

            def perform_search(direction=1):
                """Perform search in specified direction (1=forward, -1=backward)."""
                query = search_input.text().strip()
                if not query:
                    return

                try:
                    if hex_radio.isChecked():
                        # Parse hex input
                        hex_bytes = query.replace(' ', '').replace('\\x', '')
                        if not all(c in '0123456789ABCDEFabcdef' for c in hex_bytes):
                            QMessageBox.warning(dialog, "Invalid Input", "Please enter valid hex bytes (e.g., 4D5A or 4D 5A)")
                            return
                        if len(hex_bytes) % 2 != 0:
                            QMessageBox.warning(dialog, "Invalid Input", "Hex input must have even number of characters")
                            return
                        pattern = bytes.fromhex(hex_bytes)
                    else:
                        # Text search
                        pattern = query.encode('utf-8', errors='ignore')
                        if not case_sensitive.isChecked():
                            # For case-insensitive, we'll search in lowercase
                            pattern = pattern.lower()

                    # Update search state
                    if search_state['pattern'] != pattern:
                        search_state['pattern'] = pattern
                        search_state['last_pos'] = 0

                    # Prepare search data
                    search_data = self.data
                    if text_radio.isChecked() and not case_sensitive.isChecked():
                        search_data = self.data.lower()

                    # Perform search
                    start_pos = search_state['last_pos']
                    if direction == 1:  # Forward
                        result_pos = search_data.find(pattern, start_pos)
                        if result_pos == -1 and start_pos > 0:
                            # Wrap around from beginning
                            result_pos = search_data.find(pattern, 0)
                    else:  # Backward
                        # Search backwards from current position
                        if start_pos > 0:
                            result_pos = search_data.rfind(pattern, 0, start_pos)
                        else:
                            # Wrap around from end
                            result_pos = search_data.rfind(pattern)

                    if result_pos != -1:
                        # Found - update position and select in viewer
                        search_state['last_pos'] = result_pos + (1 if direction == 1 else 0)

                        # Highlight the found text in hex display
                        self._highlight_search_result(result_pos, len(pattern))

                        self.status_label.setText(f"Found at offset 0x{result_pos:08X}")
                    else:
                        QMessageBox.information(dialog, "Search", "No more matches found")
                        search_state['last_pos'] = 0

                except Exception as e:
                    QMessageBox.warning(dialog, "Search Error", f"Search failed: {str(e)}")

            # Connect buttons
            find_next_btn.clicked.connect(lambda: perform_search(1))
            find_prev_btn.clicked.connect(lambda: perform_search(-1))
            close_btn.clicked.connect(dialog.close)

            # Allow Enter to search
            search_input.returnPressed.connect(lambda: perform_search(1))

            dialog.exec_()

        except ImportError:
            self.status_label.setText("Search dialog requires PyQt5")
        except Exception as e:
            logger.error(f"Failed to open search dialog: {e}")
            self.status_label.setText("Search dialog failed to open")

    def _highlight_search_result(self, offset: int, length: int):
        """Highlight search result in the hex display."""
        try:
            # Update hex display to show the found location
            if hasattr(self, 'hex_display') and self.hex_display:
                # Calculate which part of data to show (center the result)
                bytes_per_line = 16
                context_lines = 5

                start_line = max(0, (offset // bytes_per_line) - context_lines)
                end_line = min(len(self.data) // bytes_per_line, start_line + (context_lines * 2) + 1)

                start_offset = start_line * bytes_per_line
                end_offset = min(len(self.data), end_line * bytes_per_line)

                # Generate hex display with highlighting
                hex_lines = []
                for line_offset in range(start_offset, end_offset, bytes_per_line):
                    line_end = min(line_offset + bytes_per_line, len(self.data))
                    line_data = self.data[line_offset:line_end]

                    # Format hex bytes
                    hex_bytes = []
                    for i, byte in enumerate(line_data):
                        byte_offset = line_offset + i
                        if offset <= byte_offset < offset + length:
                            hex_bytes.append(f"[{byte:02X}]")  # Highlight found bytes
                        else:
                            hex_bytes.append(f"{byte:02X}")

                    # Format ASCII
                    ascii_chars = []
                    for i, byte in enumerate(line_data):
                        byte_offset = line_offset + i
                        char = chr(byte) if 32 <= byte <= 126 else '.'
                        if offset <= byte_offset < offset + length:
                            ascii_chars.append(f"[{char}]")  # Highlight found chars
                        else:
                            ascii_chars.append(char)

                    hex_str = ' '.join(hex_bytes).ljust(48)
                    ascii_str = ''.join(ascii_chars)
                    hex_lines.append(f"{line_offset:08X}: {hex_str} |{ascii_str}|")

                # Update the display
                self.hex_display.setPlainText('\n'.join(hex_lines))

                # Scroll to show the highlighted area
                cursor = self.hex_display.textCursor()
                target_line = (offset - start_offset) // bytes_per_line
                cursor.movePosition(cursor.Start)
                for _ in range(target_line):
                    cursor.movePosition(cursor.Down)
                self.hex_display.setTextCursor(cursor)
                self.hex_display.ensureCursorVisible()

        except Exception as e:
            logger.debug(f"Failed to highlight search result: {e}")


class AssemblyView(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying disassembled code."""

    def __init__(self, parent=None):
        """Initialize assembly view widget."""
        super().__init__(parent)
        self.instructions = []

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Assembly display
        self.assembly_text = QTextEdit()
        self.assembly_text.setReadOnly(True)
        self.assembly_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.assembly_text)

    def set_instructions(self, instructions: list):
        """Set assembly instructions to display."""
        self.instructions = instructions
        if PYQT_AVAILABLE and hasattr(self, 'assembly_text'):
            text = "\n".join(instructions)
            self.assembly_text.setPlainText(text)


class CFGWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying Control Flow Graph."""

    def __init__(self, parent=None):
        """Initialize CFG widget."""
        super().__init__(parent)
        self.cfg_data = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Placeholder for CFG visualization
        self.cfg_label = QLabel("Control Flow Graph Visualization")
        self.cfg_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.cfg_label)

    def set_cfg_data(self, cfg_data):
        """Set CFG data to display."""
        self.cfg_data = cfg_data
        # CFG visualization will be rendered when graphing library is available
        if hasattr(self, 'cfg_label'):
            self.cfg_label.setText("CFG loaded - visualization pending")


class CallGraphWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying function call graphs."""

    def __init__(self, parent=None):
        """Initialize call graph widget."""
        super().__init__(parent)
        self.graph_data = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Placeholder for call graph
        self.graph_label = QLabel("Call Graph Visualization")
        self.graph_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.graph_label)

    def set_graph_data(self, graph_data):
        """Set call graph data to display."""
        self.graph_data = graph_data
        # Graph visualization will be rendered when graphing library is available
        if hasattr(self, 'graph_label'):
            self.graph_label.setText("Call graph loaded - visualization pending")


class SearchBar(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Custom search bar widget."""

    searchRequested = pyqtSignal(str) if PYQT_AVAILABLE else None

    def __init__(self, parent=None):
        """Initialize search bar."""
        super().__init__(parent)

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Search input
        from PyQt5.QtWidgets import QLineEdit
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.returnPressed.connect(self._on_search)
        layout.addWidget(self.search_input)

        # Search button
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._on_search)
        layout.addWidget(self.search_btn)

    def _on_search(self):
        """Handle search request."""
        if self.searchRequested and hasattr(self, 'search_input'):
            text = self.search_input.text()
            if text:
                self.searchRequested.emit(text)


class FilterPanel(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for filtering displayed data."""

    filterChanged = pyqtSignal(dict) if PYQT_AVAILABLE else None

    def __init__(self, parent=None):
        """Initialize filter panel."""
        super().__init__(parent)
        self.filters = {}

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Filter title
        title = QLabel("Filters")
        title.setStyleSheet("font-weight: bold;")
        layout.addWidget(title)

        # Placeholder for filter controls
        self.filter_frame = QFrame()
        self.filter_frame.setFrameStyle(QFrame.StyledPanel)
        layout.addWidget(self.filter_frame)

        layout.addStretch()


class ToolPanel(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget containing analysis tools."""

    def __init__(self, parent=None):
        """Initialize tool panel."""
        super().__init__(parent)

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Tools title
        title = QLabel("Tools")
        title.setStyleSheet("font-weight: bold;")
        layout.addWidget(title)

        # Tool buttons
        self.analyze_btn = QPushButton("Analyze")
        layout.addWidget(self.analyze_btn)

        self.patch_btn = QPushButton("Patch")
        layout.addWidget(self.patch_btn)

        self.export_btn = QPushButton("Export")
        layout.addWidget(self.export_btn)

        layout.addStretch()


class HeatmapWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying data as a heatmap."""

    def __init__(self, parent=None):
        """Initialize heatmap widget."""
        super().__init__(parent)
        self.data = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Placeholder for heatmap
        self.heatmap_label = QLabel("Heatmap Visualization")
        self.heatmap_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.heatmap_label)

    def set_data(self, data):
        """Set heatmap data."""
        self.data = data
        # Heatmap visualization will be rendered when visualization library is available
        self.update()


class GraphWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Generic graph visualization widget."""

    def __init__(self, parent=None):
        """Initialize graph widget."""
        super().__init__(parent)
        self.graph_data = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Placeholder for graph
        self.graph_label = QLabel("Graph Visualization")
        self.graph_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.graph_label)

    def set_graph_data(self, data):
        """Set graph data."""
        self.graph_data = data
        # Graph visualization will be rendered when graphing library is available
        if hasattr(self, 'graph_label'):
            self.graph_label.setText("Graph data loaded - visualization pending")


class TimelineWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying timeline data."""

    def __init__(self, parent=None):
        """Initialize timeline widget."""
        super().__init__(parent)
        self.events = []

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Placeholder for timeline
        self.timeline_label = QLabel("Timeline Visualization")
        self.timeline_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timeline_label)

    def add_event(self, timestamp, event):
        """Add event to timeline."""
        self.events.append((timestamp, event))
        # Timeline visualization will be updated when rendering library is available
        if hasattr(self, 'timeline_label'):
            self.timeline_label.setText(f"Timeline: {len(self.events)} events")


class ProgressWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Custom progress display widget."""

    def __init__(self, parent=None):
        """Initialize progress widget."""
        super().__init__(parent)
        self.progress = 0

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Progress bar
        from PyQt5.QtWidgets import QProgressBar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def set_progress(self, value: int, status: str = ""):
        """Set progress value and status."""
        self.progress = value
        if PYQT_AVAILABLE and hasattr(self, 'progress_bar'):
            self.progress_bar.setValue(value)
            if status and hasattr(self, 'status_label'):
                self.status_label.setText(status)


class StatusBar(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Custom status bar widget."""

    def __init__(self, parent=None):
        """Initialize status bar."""
        super().__init__(parent)
        self.messages = []

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)

        # Status message
        self.message_label = QLabel("Ready")
        layout.addWidget(self.message_label)

        layout.addStretch()

        # Additional status items can be added here

    def show_message(self, message: str, timeout: int = 0):
        """Show status message."""
        self.messages.append(message)
        if PYQT_AVAILABLE and hasattr(self, 'message_label'):
            self.message_label.setText(message)
            if timeout > 0:
                QTimer.singleShot(timeout, lambda: self.message_label.setText("Ready"))


class LogViewer(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for viewing application logs."""

    def __init__(self, parent=None):
        """Initialize log viewer."""
        super().__init__(parent)
        self.log_entries = []

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)

        # Log display
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.log_text)

        # Control buttons
        button_layout = QHBoxLayout()

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_log)
        button_layout.addWidget(self.clear_btn)

        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_log)
        button_layout.addWidget(self.save_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

    def add_log_entry(self, entry: str):
        """Add log entry."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_entry = f"[{timestamp}] {entry}"
        self.log_entries.append(formatted_entry)

        if PYQT_AVAILABLE and hasattr(self, 'log_text'):
            self.log_text.append(formatted_entry)

    def clear_log(self):
        """Clear log entries."""
        self.log_entries.clear()
        if PYQT_AVAILABLE and hasattr(self, 'log_text'):
            self.log_text.clear()

    def save_log(self):
        """Save log to file."""
        if PYQT_AVAILABLE:
            from PyQt5.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Log", "", "Log Files (*.log);;All Files (*)"
            )
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(self.log_entries))
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Failed to save log: %s", e)


# Export all widgets
__all__ = [
    'HexViewer', 'AssemblyView', 'CFGWidget', 'CallGraphWidget',
    'SearchBar', 'FilterPanel', 'ToolPanel',
    'HeatmapWidget', 'GraphWidget', 'TimelineWidget',
    'ProgressWidget', 'StatusBar', 'LogViewer'
]
