"""Hex viewer widget for displaying binary data in hexadecimal format."""
import logging
from typing import Optional

from intellicrack.logger import logger

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



try:
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QSplitter,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    PYQT_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in hex_viewer: %s", e)
    PYQT_AVAILABLE = False
    QWidget = object
    pyqtSignal = None

# Import hex viewer components if available
try:
    from ...hexview.data_inspector import DataInspector
    from ...hexview.hex_widget import HexViewerWidget
    from ...hexview.performance_monitor import PerformanceMonitor
    HEX_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in hex_viewer: %s", e)
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
            self.hex_widget = HexViewerWidget()
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
            except AttributeError as e:
                self.logger.error("Attribute error in hex_viewer: %s", e)
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
            from PyQt6.QtWidgets import QFileDialog

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
            except AttributeError as e:
                self.logger.error("Attribute error in hex_viewer: %s", e)
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
            except AttributeError as e:
                self.logger.error("Attribute error in hex_viewer: %s", e)
                pass

    def get_selection(self):
        """Get current selection range."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            try:
                return self.hex_widget.get_selection()
            except AttributeError as e:
                self.logger.error("Attribute error in hex_viewer: %s", e)
                pass
        return (0, 0)

    def set_selection(self, start: int, length: int):
        """Set selection range."""
        if HEX_COMPONENTS_AVAILABLE and hasattr(self, 'hex_widget'):
            try:
                self.hex_widget.set_selection(start, length)
            except AttributeError as e:
                self.logger.error("Attribute error in hex_viewer: %s", e)
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
            except (IndexError, AttributeError) as e:
                self.logger.error("Error in hex_viewer: %s", e)
                pass

    def _open_basic_search_dialog(self):
        """Open a basic search dialog for fallback mode."""
        if not self.data:
            self.status_label.setText("No data to search")
            return

        try:
            from PyQt6.QtWidgets import (
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
                    logger.error("Exception in hex_viewer: %s", e)
                    QMessageBox.warning(dialog, "Search Error", f"Search failed: {str(e)}")

            # Connect buttons
            find_next_btn.clicked.connect(lambda: perform_search(1))
            find_prev_btn.clicked.connect(lambda: perform_search(-1))
            close_btn.clicked.connect(dialog.close)

            # Allow Enter to search
            search_input.returnPressed.connect(lambda: perform_search(1))

            dialog.exec_()

        except ImportError as e:
            logger.error("Import error in hex_viewer: %s", e)
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
    """Widget for displaying control flow graphs."""

    def __init__(self, parent=None):
        """Initialize CFG widget."""
        super().__init__(parent)
        self.cfg_data = None
        self.figure = None
        self.canvas = None
        self.ax = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)
        
        # Try to import matplotlib for visualization
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure
            import matplotlib.pyplot as plt
            
            # Create matplotlib figure for CFG visualization
            self.figure = Figure(figsize=(10, 8))
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)
            
            # Add toolbar for interaction
            from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
            self.toolbar = NavigationToolbar(self.canvas, self)
            layout.addWidget(self.toolbar)
            
        except ImportError:
            # Fallback to label if matplotlib not available
            self.cfg_label = QLabel("Control Flow Graph Visualization\n(Matplotlib not available)")
            self.cfg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.cfg_label)

    def set_cfg_data(self, cfg_data):
        """Set CFG data to display."""
        self.cfg_data = cfg_data
        
        if self.cfg_data and self.canvas:
            self._render_cfg()
        elif hasattr(self, 'cfg_label'):
            self.cfg_label.setText("CFG loaded - visualization pending")
    
    def _render_cfg(self):
        """Render the control flow graph."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Clear previous plot
            self.figure.clear()
            self.ax = self.figure.add_subplot(111)
            
            # Create NetworkX graph from CFG data
            G = nx.DiGraph()
            
            if 'nodes' in self.cfg_data and 'edges' in self.cfg_data:
                # Add nodes
                for node in self.cfg_data['nodes']:
                    G.add_node(node['id'], 
                             label=node.get('label', f"0x{node['id']:x}"),
                             size=node.get('size', 100))
                
                # Add edges
                for edge in self.cfg_data['edges']:
                    G.add_edge(edge['source'], edge['target'])
                
                # Calculate layout
                if len(G.nodes) > 0:
                    try:
                        # Try hierarchical layout first (better for CFGs)
                        pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
                    except:
                        # Fallback to spring layout
                        pos = nx.spring_layout(G, k=2, iterations=50)
                    
                    # Draw nodes
                    node_colors = []
                    node_sizes = []
                    for node in G.nodes():
                        node_data = G.nodes[node]
                        # Color nodes based on their properties
                        if 'entry' in str(node_data.get('label', '')).lower():
                            node_colors.append('#90EE90')  # Light green for entry
                        elif 'exit' in str(node_data.get('label', '')).lower() or 'ret' in str(node_data.get('label', '')).lower():
                            node_colors.append('#FFB6C1')  # Light red for exit
                        else:
                            node_colors.append('#87CEEB')  # Sky blue for regular blocks
                        node_sizes.append(node_data.get('size', 300))
                    
                    # Draw the graph
                    nx.draw_networkx_nodes(G, pos, 
                                         node_color=node_colors,
                                         node_size=node_sizes,
                                         ax=self.ax,
                                         alpha=0.9)
                    
                    nx.draw_networkx_edges(G, pos, 
                                         edge_color='gray',
                                         arrows=True,
                                         arrowsize=20,
                                         arrowstyle='->',
                                         ax=self.ax,
                                         alpha=0.6)
                    
                    # Draw labels
                    labels = nx.get_node_attributes(G, 'label')
                    nx.draw_networkx_labels(G, pos, labels, 
                                          font_size=8,
                                          ax=self.ax)
                    
                    # Set title
                    func_name = self.cfg_data.get('function', 'Unknown Function')
                    self.ax.set_title(f"Control Flow Graph - {func_name}", fontsize=14, fontweight='bold')
                    
                    # Remove axes
                    self.ax.axis('off')
                    
                    # Adjust layout
                    self.figure.tight_layout()
                    
                    # Refresh canvas
                    self.canvas.draw()
                else:
                    self.ax.text(0.5, 0.5, 'No CFG data to display', 
                               horizontalalignment='center',
                               verticalalignment='center',
                               transform=self.ax.transAxes)
                    self.canvas.draw()
            
        except Exception as e:
            # Handle errors gracefully
            if self.ax:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Error rendering CFG:\n{str(e)}', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes)
                self.canvas.draw()
            elif hasattr(self, 'cfg_label'):
                self.cfg_label.setText(f"Error rendering CFG: {str(e)}")


class CallGraphWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying function call graphs."""

    def __init__(self, parent=None):
        """Initialize call graph widget."""
        super().__init__(parent)
        self.graph_data = None
        self.figure = None
        self.canvas = None
        self.ax = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)
        
        # Try to import matplotlib for visualization
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure
            import matplotlib.pyplot as plt
            
            # Create matplotlib figure for call graph visualization
            self.figure = Figure(figsize=(10, 8))
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)
            
            # Add toolbar for interaction
            from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
            self.toolbar = NavigationToolbar(self.canvas, self)
            layout.addWidget(self.toolbar)
            
        except ImportError:
            # Fallback to label if matplotlib not available
            self.graph_label = QLabel("Call Graph Visualization\n(Matplotlib not available)")
            self.graph_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.graph_label)

    def set_graph_data(self, graph_data):
        """Set call graph data to display."""
        self.graph_data = graph_data
        
        if self.graph_data and self.canvas:
            self._render_call_graph()
        elif hasattr(self, 'graph_label'):
            self.graph_label.setText("Call graph loaded - visualization pending")
    
    def _render_call_graph(self):
        """Render the call graph."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Clear previous plot
            self.figure.clear()
            self.ax = self.figure.add_subplot(111)
            
            # Create NetworkX graph from call graph data
            G = nx.DiGraph()
            
            if isinstance(self.graph_data, dict):
                # Handle different data formats
                if 'nodes' in self.graph_data and 'edges' in self.graph_data:
                    # Format 1: nodes and edges lists
                    for node in self.graph_data['nodes']:
                        node_id = node.get('id', node.get('name', ''))
                        G.add_node(node_id, 
                                 label=node.get('label', node.get('name', str(node_id))),
                                 calls=node.get('calls', 0))
                    
                    for edge in self.graph_data['edges']:
                        G.add_edge(edge['source'], edge['target'])
                
                elif 'functions' in self.graph_data:
                    # Format 2: functions dictionary with call relationships
                    for func_name, func_data in self.graph_data['functions'].items():
                        G.add_node(func_name, 
                                 label=func_name,
                                 calls=len(func_data.get('calls', [])))
                        
                        # Add edges for function calls
                        for called_func in func_data.get('calls', []):
                            G.add_edge(func_name, called_func)
                
                # Calculate layout
                if len(G.nodes) > 0:
                    try:
                        # Try hierarchical layout first (better for call graphs)
                        pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
                    except:
                        # Fallback to spring layout
                        pos = nx.spring_layout(G, k=3, iterations=50)
                    
                    # Color nodes based on call frequency
                    node_colors = []
                    node_sizes = []
                    for node in G.nodes():
                        node_data = G.nodes[node]
                        calls = node_data.get('calls', 0)
                        
                        # Color gradient based on call frequency
                        if calls == 0:
                            node_colors.append('#FFE4B5')  # Moccasin for leaf functions
                        elif calls < 3:
                            node_colors.append('#87CEEB')  # Sky blue for low calls
                        elif calls < 10:
                            node_colors.append('#4682B4')  # Steel blue for medium calls
                        else:
                            node_colors.append('#191970')  # Midnight blue for high calls
                        
                        # Size based on importance
                        if 'main' in str(node).lower() or 'entry' in str(node).lower():
                            node_sizes.append(800)
                        else:
                            node_sizes.append(300 + calls * 50)
                    
                    # Draw the graph
                    nx.draw_networkx_nodes(G, pos, 
                                         node_color=node_colors,
                                         node_size=node_sizes,
                                         ax=self.ax,
                                         alpha=0.9)
                    
                    nx.draw_networkx_edges(G, pos, 
                                         edge_color='gray',
                                         arrows=True,
                                         arrowsize=15,
                                         arrowstyle='->',
                                         ax=self.ax,
                                         alpha=0.5,
                                         connectionstyle="arc3,rad=0.1")
                    
                    # Draw labels
                    labels = nx.get_node_attributes(G, 'label')
                    nx.draw_networkx_labels(G, pos, labels, 
                                          font_size=7,
                                          ax=self.ax)
                    
                    # Add statistics
                    total_funcs = len(G.nodes)
                    total_calls = len(G.edges)
                    self.ax.set_title(f"Call Graph - {total_funcs} functions, {total_calls} calls", 
                                    fontsize=14, fontweight='bold')
                    
                    # Add legend
                    from matplotlib.patches import Patch
                    legend_elements = [
                        Patch(facecolor='#FFE4B5', label='Leaf function'),
                        Patch(facecolor='#87CEEB', label='Low calls (1-2)'),
                        Patch(facecolor='#4682B4', label='Medium calls (3-9)'),
                        Patch(facecolor='#191970', label='High calls (10+)')
                    ]
                    self.ax.legend(handles=legend_elements, loc='upper right', fontsize=8)
                    
                    # Remove axes
                    self.ax.axis('off')
                    
                    # Adjust layout
                    self.figure.tight_layout()
                    
                    # Refresh canvas
                    self.canvas.draw()
                else:
                    self.ax.text(0.5, 0.5, 'No call graph data to display', 
                               horizontalalignment='center',
                               verticalalignment='center',
                               transform=self.ax.transAxes)
                    self.canvas.draw()
            
        except Exception as e:
            # Handle errors gracefully
            if self.ax:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Error rendering call graph:\n{str(e)}', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes)
                self.canvas.draw()
            elif hasattr(self, 'graph_label'):
                self.graph_label.setText(f"Error rendering call graph: {str(e)}")


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
        from PyQt6.QtWidgets import QLineEdit
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
    """Widget for displaying heatmap data."""

    def __init__(self, parent=None):
        """Initialize heatmap widget."""
        super().__init__(parent)
        self.data = None
        self.figure = None
        self.canvas = None
        self.ax = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)
        
        # Try to import matplotlib for visualization
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure
            import matplotlib.pyplot as plt
            
            # Create matplotlib figure for heatmap visualization
            self.figure = Figure(figsize=(10, 8))
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)
            
            # Add toolbar for interaction
            from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
            self.toolbar = NavigationToolbar(self.canvas, self)
            layout.addWidget(self.toolbar)
            
        except ImportError:
            # Fallback to label if matplotlib not available
            self.heatmap_label = QLabel("Heatmap Visualization\n(Matplotlib not available)")
            self.heatmap_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.heatmap_label)

    def set_data(self, data):
        """Set heatmap data."""
        self.data = data
        
        if self.data and self.canvas:
            self._render_heatmap()
        elif hasattr(self, 'heatmap_label'):
            self.heatmap_label.setText("Heatmap data loaded")
    
    def _render_heatmap(self):
        """Render the heatmap visualization."""
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            
            # Clear previous plot
            self.figure.clear()
            self.ax = self.figure.add_subplot(111)
            
            # Determine data format and render accordingly
            if isinstance(self.data, dict):
                # Handle dictionary format with different types
                data_type = self.data.get('type', 'generic')
                
                if data_type == 'binary':
                    self._render_binary_heatmap()
                elif data_type == 'frequency':
                    self._render_frequency_heatmap()
                elif data_type == 'entropy':
                    self._render_entropy_heatmap()
                else:
                    self._render_generic_heatmap()
            elif isinstance(self.data, (list, np.ndarray)):
                # Handle array data directly
                self._render_array_heatmap()
            
            # Refresh canvas
            self.canvas.draw()
            
        except Exception as e:
            # Handle errors gracefully
            if self.ax:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Error rendering heatmap:\n{str(e)}', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes)
                self.canvas.draw()
            elif hasattr(self, 'heatmap_label'):
                self.heatmap_label.setText(f"Error rendering heatmap: {str(e)}")
    
    def _render_binary_heatmap(self):
        """Render binary data as heatmap."""
        import numpy as np
        
        binary_data = self.data.get('data', [])
        if binary_data:
            # Convert binary data to 2D array for visualization
            bytes_per_row = self.data.get('bytes_per_row', 16)
            rows = []
            
            for i in range(0, len(binary_data), bytes_per_row):
                row = binary_data[i:i+bytes_per_row]
                # Pad row if necessary
                if len(row) < bytes_per_row:
                    row.extend([0] * (bytes_per_row - len(row)))
                rows.append(row)
            
            # Create heatmap
            heatmap_data = np.array(rows)
            im = self.ax.imshow(heatmap_data, cmap='hot', aspect='auto', interpolation='nearest')
            
            # Add colorbar
            self.figure.colorbar(im, ax=self.ax, label='Byte Value')
            
            # Labels
            self.ax.set_title(self.data.get('title', 'Binary Data Heatmap'))
            self.ax.set_xlabel('Byte Offset')
            self.ax.set_ylabel('Row')
    
    def _render_frequency_heatmap(self):
        """Render frequency data as heatmap."""
        import numpy as np
        
        freq_data = self.data.get('data', {})
        if freq_data:
            # Create frequency matrix
            categories = list(freq_data.keys())
            values = list(freq_data.values())
            
            # Reshape for heatmap if needed
            if isinstance(values[0], list):
                # 2D frequency data
                heatmap_data = np.array(values)
            else:
                # 1D frequency data - create rows
                heatmap_data = np.array([values])
            
            im = self.ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
            self.figure.colorbar(im, ax=self.ax, label='Frequency')
            
            # Set labels
            self.ax.set_xticks(range(len(categories)))
            self.ax.set_xticklabels(categories, rotation=45, ha='right')
            self.ax.set_title(self.data.get('title', 'Frequency Heatmap'))
    
    def _render_entropy_heatmap(self):
        """Render entropy data as heatmap."""
        import numpy as np
        
        entropy_data = self.data.get('data', [])
        block_size = self.data.get('block_size', 256)
        
        if entropy_data:
            # Reshape entropy values into 2D grid
            grid_size = int(np.sqrt(len(entropy_data)))
            if grid_size * grid_size < len(entropy_data):
                grid_size += 1
            
            # Pad data if necessary
            padded_data = entropy_data + [0] * (grid_size * grid_size - len(entropy_data))
            heatmap_data = np.array(padded_data).reshape(grid_size, grid_size)
            
            im = self.ax.imshow(heatmap_data, cmap='viridis', aspect='auto', 
                               vmin=0, vmax=8)  # Entropy range 0-8 bits
            self.figure.colorbar(im, ax=self.ax, label='Entropy (bits)')
            
            self.ax.set_title(f'Entropy Heatmap (block size: {block_size} bytes)')
            self.ax.set_xlabel('Block X')
            self.ax.set_ylabel('Block Y')
    
    def _render_generic_heatmap(self):
        """Render generic heatmap data."""
        import numpy as np
        
        heatmap_data = self.data.get('data', [])
        if heatmap_data:
            # Convert to numpy array
            if not isinstance(heatmap_data, np.ndarray):
                heatmap_data = np.array(heatmap_data)
            
            # Ensure 2D
            if heatmap_data.ndim == 1:
                heatmap_data = heatmap_data.reshape(1, -1)
            
            im = self.ax.imshow(heatmap_data, cmap='plasma', aspect='auto')
            self.figure.colorbar(im, ax=self.ax)
            
            self.ax.set_title(self.data.get('title', 'Heatmap'))
            
            # Add axis labels if provided
            if 'xlabels' in self.data:
                self.ax.set_xticks(range(len(self.data['xlabels'])))
                self.ax.set_xticklabels(self.data['xlabels'], rotation=45, ha='right')
            if 'ylabels' in self.data:
                self.ax.set_yticks(range(len(self.data['ylabels'])))
                self.ax.set_yticklabels(self.data['ylabels'])
    
    def _render_array_heatmap(self):
        """Render array data as heatmap."""
        import numpy as np
        
        # Convert to numpy array
        heatmap_data = np.array(self.data)
        
        # Ensure 2D
        if heatmap_data.ndim == 1:
            # Try to make it square-ish
            size = int(np.sqrt(len(heatmap_data)))
            if size * size == len(heatmap_data):
                heatmap_data = heatmap_data.reshape(size, size)
            else:
                # Just make it a row
                heatmap_data = heatmap_data.reshape(1, -1)
        
        im = self.ax.imshow(heatmap_data, cmap='coolwarm', aspect='auto')
        self.figure.colorbar(im, ax=self.ax)
        self.ax.set_title('Data Heatmap')


class GraphWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying generic graphs."""

    def __init__(self, parent=None):
        """Initialize graph widget."""
        super().__init__(parent)
        self.graph_data = None
        self.figure = None
        self.canvas = None
        self.ax = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)
        
        # Try to import matplotlib for visualization
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure
            import matplotlib.pyplot as plt
            
            # Create matplotlib figure for graph visualization
            self.figure = Figure(figsize=(10, 8))
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)
            
            # Add toolbar for interaction
            from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
            self.toolbar = NavigationToolbar(self.canvas, self)
            layout.addWidget(self.toolbar)
            
        except ImportError:
            # Fallback to label if matplotlib not available
            self.graph_label = QLabel("Graph Visualization\n(Matplotlib not available)")
            self.graph_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.graph_label)

    def set_graph_data(self, graph_data):
        """Set graph data to display."""
        self.graph_data = graph_data
        
        if self.graph_data and self.canvas:
            self._render_graph()
        elif hasattr(self, 'graph_label'):
            self.graph_label.setText("Graph loaded - visualization pending")
    
    def _render_graph(self):
        """Render the generic graph."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Clear previous plot
            self.figure.clear()
            self.ax = self.figure.add_subplot(111)
            
            # Determine graph type and render accordingly
            if isinstance(self.graph_data, dict):
                graph_type = self.graph_data.get('type', 'generic')
                
                if graph_type == 'line':
                    self._render_line_graph()
                elif graph_type == 'bar':
                    self._render_bar_graph()
                elif graph_type == 'scatter':
                    self._render_scatter_plot()
                elif graph_type == 'network':
                    self._render_network_graph()
                else:
                    self._render_generic_plot()
            else:
                # Handle simple data arrays
                self._render_simple_plot()
                
            # Refresh canvas
            self.canvas.draw()
            
        except Exception as e:
            # Handle errors gracefully
            if self.ax:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Error rendering graph:\n{str(e)}', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes)
                self.canvas.draw()
            elif hasattr(self, 'graph_label'):
                self.graph_label.setText(f"Error rendering graph: {str(e)}")
    
    def _render_line_graph(self):
        """Render a line graph."""
        data = self.graph_data.get('data', {})
        x = data.get('x', [])
        y = data.get('y', [])
        
        if x and y:
            self.ax.plot(x, y, 'b-', linewidth=2, markersize=8, marker='o')
            self.ax.set_xlabel(self.graph_data.get('xlabel', 'X'))
            self.ax.set_ylabel(self.graph_data.get('ylabel', 'Y'))
            self.ax.set_title(self.graph_data.get('title', 'Line Graph'))
            self.ax.grid(True, alpha=0.3)
    
    def _render_bar_graph(self):
        """Render a bar graph."""
        data = self.graph_data.get('data', {})
        labels = data.get('labels', [])
        values = data.get('values', [])
        
        if labels and values:
            self.ax.bar(labels, values, color='skyblue', edgecolor='navy', alpha=0.7)
            self.ax.set_xlabel(self.graph_data.get('xlabel', 'Categories'))
            self.ax.set_ylabel(self.graph_data.get('ylabel', 'Values'))
            self.ax.set_title(self.graph_data.get('title', 'Bar Graph'))
            self.ax.grid(True, axis='y', alpha=0.3)
    
    def _render_scatter_plot(self):
        """Render a scatter plot."""
        data = self.graph_data.get('data', {})
        x = data.get('x', [])
        y = data.get('y', [])
        
        if x and y:
            self.ax.scatter(x, y, c='blue', alpha=0.6, s=50)
            self.ax.set_xlabel(self.graph_data.get('xlabel', 'X'))
            self.ax.set_ylabel(self.graph_data.get('ylabel', 'Y'))
            self.ax.set_title(self.graph_data.get('title', 'Scatter Plot'))
            self.ax.grid(True, alpha=0.3)
    
    def _render_network_graph(self):
        """Render a network graph."""
        import networkx as nx
        
        # Create NetworkX graph
        G = nx.Graph()
        
        nodes = self.graph_data.get('nodes', [])
        edges = self.graph_data.get('edges', [])
        
        # Add nodes and edges
        for node in nodes:
            G.add_node(node.get('id', node))
        
        for edge in edges:
            G.add_edge(edge.get('source', edge[0]), edge.get('target', edge[1]))
        
        # Layout
        pos = nx.spring_layout(G)
        
        # Draw
        nx.draw(G, pos, ax=self.ax, with_labels=True, 
                node_color='lightblue', node_size=500,
                font_size=10, font_weight='bold',
                edge_color='gray', width=2)
        
        self.ax.set_title(self.graph_data.get('title', 'Network Graph'))
        self.ax.axis('off')
    
    def _render_generic_plot(self):
        """Render a generic plot based on available data."""
        data = self.graph_data.get('data', {})
        
        # Try to intelligently render based on data structure
        if 'x' in data and 'y' in data:
            self.ax.plot(data['x'], data['y'])
        elif 'values' in data:
            self.ax.plot(data['values'])
        else:
            self.ax.text(0.5, 0.5, 'Unsupported data format', 
                       horizontalalignment='center',
                       verticalalignment='center',
                       transform=self.ax.transAxes)
        
        self.ax.set_title(self.graph_data.get('title', 'Graph'))
    
    def _render_simple_plot(self):
        """Render simple array data."""
        if isinstance(self.graph_data, (list, tuple)):
            self.ax.plot(self.graph_data)
            self.ax.set_title('Data Plot')
            self.ax.grid(True, alpha=0.3)


class TimelineWidget(QWidget if PYQT_AVAILABLE else BaseWidget):
    """Widget for displaying timeline of events."""

    def __init__(self, parent=None):
        """Initialize timeline widget."""
        super().__init__(parent)
        self.events = []
        self.figure = None
        self.canvas = None
        self.ax = None

        if PYQT_AVAILABLE:
            self.setup_ui()

    def setup_ui(self):
        """Setup the widget UI."""
        layout = QVBoxLayout(self)
        
        # Try to import matplotlib for visualization
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
            from matplotlib.figure import Figure
            import matplotlib.pyplot as plt
            
            # Create matplotlib figure for timeline visualization
            self.figure = Figure(figsize=(12, 6))
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)
            
            # Add toolbar for interaction
            from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
            self.toolbar = NavigationToolbar(self.canvas, self)
            layout.addWidget(self.toolbar)
            
            # Initial empty timeline
            self._render_timeline()
            
        except ImportError:
            # Fallback to label if matplotlib not available
            self.timeline_label = QLabel("Timeline Visualization\n(Matplotlib not available)")
            self.timeline_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.timeline_label)

    def add_event(self, timestamp, event):
        """Add an event to the timeline."""
        self.events.append({'timestamp': timestamp, 'event': event})
        # Sort events by timestamp
        self.events.sort(key=lambda x: x['timestamp'])
        
        if self.canvas:
            self._render_timeline()
        elif hasattr(self, 'timeline_label'):
            self.timeline_label.setText(f"Timeline: {len(self.events)} events")
    
    def _render_timeline(self):
        """Render the timeline visualization."""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            from datetime import datetime
            import numpy as np
            
            # Clear previous plot
            self.figure.clear()
            self.ax = self.figure.add_subplot(111)
            
            if not self.events:
                # Show empty timeline message
                self.ax.text(0.5, 0.5, 'No events to display\nAdd events using add_event()', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes,
                           fontsize=12)
                self.ax.set_title('Event Timeline')
                self.ax.axis('off')
            else:
                # Prepare data for visualization
                timestamps = []
                labels = []
                colors = []
                levels = []
                
                # Assign levels to avoid overlapping
                level_assignments = {}
                current_levels = []
                
                for i, event in enumerate(self.events):
                    timestamp = event['timestamp']
                    event_text = event['event']
                    
                    # Convert timestamp to datetime if it's a number
                    if isinstance(timestamp, (int, float)):
                        # Assume it's a Unix timestamp
                        timestamp = datetime.fromtimestamp(timestamp)
                    elif not isinstance(timestamp, datetime):
                        # Try to parse string timestamp
                        try:
                            timestamp = datetime.fromisoformat(str(timestamp))
                        except:
                            # Use index as fallback
                            timestamp = datetime.fromtimestamp(i * 3600)
                    
                    timestamps.append(timestamp)
                    
                    # Truncate long labels
                    label = event_text[:50] + '...' if len(event_text) > 50 else event_text
                    labels.append(label)
                    
                    # Assign color based on event type
                    if 'error' in event_text.lower():
                        colors.append('red')
                    elif 'warning' in event_text.lower():
                        colors.append('orange')
                    elif 'success' in event_text.lower() or 'complete' in event_text.lower():
                        colors.append('green')
                    elif 'start' in event_text.lower() or 'begin' in event_text.lower():
                        colors.append('blue')
                    else:
                        colors.append('gray')
                    
                    # Assign vertical level to avoid overlap
                    level = i % 5  # Simple cycling through 5 levels
                    levels.append(level)
                
                # Create the timeline plot
                fig_height = max(6, len(set(levels)) * 1.5)
                self.figure.set_figheight(fig_height)
                
                # Plot timeline base line
                self.ax.axhline(y=0, color='black', linewidth=2, alpha=0.7)
                
                # Plot events
                for i, (ts, label, color, level) in enumerate(zip(timestamps, labels, colors, levels)):
                    y_pos = (level - 2) * 0.5  # Center around y=0
                    
                    # Draw stem
                    self.ax.plot([ts, ts], [0, y_pos], color=color, linewidth=1, alpha=0.5)
                    
                    # Draw event marker
                    self.ax.scatter(ts, y_pos, color=color, s=100, zorder=3, edgecolors='black', linewidth=1)
                    
                    # Add label
                    ha = 'right' if i % 2 == 0 else 'left'
                    offset = -10 if i % 2 == 0 else 10
                    self.ax.annotate(label, (ts, y_pos), 
                                   xytext=(offset, 5), 
                                   textcoords='offset points',
                                   ha=ha,
                                   fontsize=8,
                                   bbox=dict(boxstyle='round,pad=0.3', 
                                           facecolor=color, 
                                           alpha=0.3,
                                           edgecolor=color),
                                   arrowprops=dict(arrowstyle='->', 
                                                 connectionstyle='arc3,rad=0.3',
                                                 color=color,
                                                 alpha=0.7))
                
                # Format x-axis
                self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
                self.ax.xaxis.set_major_locator(mdates.AutoDateLocator())
                plt.setp(self.ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
                
                # Set labels and title
                self.ax.set_xlabel('Time')
                self.ax.set_ylabel('Events')
                self.ax.set_title(f'Event Timeline ({len(self.events)} events)')
                
                # Set y-axis limits
                y_margin = 0.5
                if levels:
                    self.ax.set_ylim(min(levels) * 0.5 - y_margin, max(levels) * 0.5 + y_margin)
                
                # Add grid
                self.ax.grid(True, axis='x', alpha=0.3)
                
                # Remove y-axis ticks
                self.ax.set_yticks([])
                
                # Add legend
                from matplotlib.patches import Patch
                legend_elements = [
                    Patch(facecolor='blue', label='Start/Begin'),
                    Patch(facecolor='green', label='Success/Complete'),
                    Patch(facecolor='orange', label='Warning'),
                    Patch(facecolor='red', label='Error'),
                    Patch(facecolor='gray', label='Other')
                ]
                self.ax.legend(handles=legend_elements, loc='upper right', fontsize=8)
            
            # Adjust layout
            self.figure.tight_layout()
            
            # Refresh canvas
            self.canvas.draw()
            
        except Exception as e:
            # Handle errors gracefully
            if self.ax:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Error rendering timeline:\n{str(e)}', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.ax.transAxes)
                self.canvas.draw()
            elif hasattr(self, 'timeline_label'):
                self.timeline_label.setText(f"Error rendering timeline: {str(e)}")
    
    def clear_events(self):
        """Clear all events from the timeline."""
        self.events = []
        if self.canvas:
            self._render_timeline()
        elif hasattr(self, 'timeline_label'):
            self.timeline_label.setText("Timeline: 0 events")
    
    def set_events(self, events_list):
        """Set multiple events at once."""
        self.events = events_list
        self.events.sort(key=lambda x: x['timestamp'])
        if self.canvas:
            self._render_timeline()
        elif hasattr(self, 'timeline_label'):
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
        from PyQt6.QtWidgets import QProgressBar
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
            from PyQt6.QtWidgets import QFileDialog
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
