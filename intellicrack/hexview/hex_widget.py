"""
Hex viewer widget for displaying and editing binary data.

This module provides the main hex viewer widget for Intellicrack,
combining file access, rendering, and highlighting into a cohesive UI.
"""

import logging
import os
from typing import List, Optional, Tuple, Union

from PyQt5.QtCore import QPoint, QRect, Qt, pyqtSignal
from PyQt5.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
    QResizeEvent,
)
from PyQt5.QtWidgets import (
    QAbstractScrollArea,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
)

from .file_handler import VirtualFileAccess
from .hex_highlighter import HexHighlight, HexHighlighter, HighlightType
from .hex_renderer import HexViewRenderer, ViewMode, parse_hex_view
from .performance_monitor import PerformanceMonitor

logger = logging.getLogger('Intellicrack.HexView')


class HexViewerWidget(QAbstractScrollArea):
    """
    Widget for displaying and editing binary data in a hex format.

    This widget provides a fully featured hex viewer and editor, capable of:
    - Viewing data in hex, decimal, or binary format
    - Efficiently handling large files
    - Highlighting regions of interest
    - Editing data
    - Searching for patterns
    - Integration with Intellicrack's AI functions
    """

    # Signals
    data_changed = pyqtSignal(int, int)  # (offset, size)
    selection_changed = pyqtSignal(int, int)  # (start, end)
    offset_changed = pyqtSignal(int)  # Current offset
    view_mode_changed = pyqtSignal(ViewMode)  # Current view mode

    def __init__(self, parent=None):
        """Initialize the hex viewer widget."""
        super().__init__(parent)

        # Initialize members
        self.file_handler = None
        self.file_path = ""
        self.view_mode = ViewMode.HEX
        self.bytes_per_row = 16
        self.group_size = 1
        self.renderer = HexViewRenderer(bytes_per_row=self.bytes_per_row)
        self.highlighter = HexHighlighter()
        self.current_offset = 0
        self.selection_start = -1
        self.selection_end = -1
        self.editing_offset = -1
        self.editing_text = ""

        # Performance monitoring
        self.performance_monitor = PerformanceMonitor()

        # UI settings
        self.header_height = 30
        self.address_width = 90
        self.gutter_width = 5
        self.char_width = 0
        self.char_height = 0
        self.hex_offset_x = self.address_width + self.gutter_width
        self.ascii_offset_x = 0  # Will be calculated when drawing

        # Colors - Ensuring high contrast for visibility
        self.bg_color = QColor(245, 245, 245)  # Light gray background
        self.text_color = QColor(20, 20, 20)   # Near black text
        self.header_bg_color = QColor(220, 220, 220)  # Slightly darker header
        self.header_text_color = QColor(0, 0, 0)      # Black header text
        self.address_bg_color = QColor(220, 220, 220)
        self.address_text_color = QColor(40, 40, 40)  # Darker address text
        self.selection_color = QColor(173, 214, 255, 160)  # Increased opacity
        self.highlight_selection_color = QColor(255, 255, 0, 160)
        self.modified_color = QColor(255, 180, 180)  # Slightly more intense

        # Setup the widget
        self.setup_ui()
        self.update_scrollbars()

        logger.debug("HexViewerWidget initialized")

    def setup_ui(self):
        """Set up the UI components."""
        # Set up font with better visibility
        font = QFont("Courier New", 11)  # Slightly larger font
        font.setFixedPitch(True)
        font.setBold(True)  # Make font bold for better visibility
        font.setStyleStrategy(QFont.PreferAntialias)  # Enable anti-aliasing for smoother text
        self.setFont(font)

        # Calculate sizes based on font
        fm = QFontMetrics(font)
        self.char_width = fm.horizontalAdvance('0')
        self.char_height = fm.height()

        # Set viewport size, we will adjust it later
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        # Set focus policy to accept focus
        self.setFocusPolicy(Qt.StrongFocus)

        # Set up scrollbars
        self.horizontalScrollBar().setSingleStep(self.char_width)
        self.horizontalScrollBar().setPageStep(self.char_width * 8)
        self.verticalScrollBar().setSingleStep(self.char_height)
        self.verticalScrollBar().setPageStep(self.char_height * 4)

        # Configure widget behavior
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        # Create context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

        # Connect scrollbar signals
        self.verticalScrollBar().valueChanged.connect(self.handle_scroll)
        self.horizontalScrollBar().valueChanged.connect(self.viewport().update)

    def load_file(self, file_path: str, read_only: bool = True) -> bool:
        """
        Load a file into the hex viewer.

        Args:
            file_path: Path to the file to load
            read_only: Whether the file should be opened in read-only mode

        Returns:
            True if the file was loaded successfully, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error("File not found: %s", file_path)
            return False

        logger.debug("HexWidget.load_file: Loading %s, read_only=%s", file_path, read_only)
        try:
            # Log detailed debugging info
            logger.info("HexWidget.load_file: Loading %s, read_only=%s", file_path, read_only)

            # Check access permissions
            if not os.access(file_path, os.R_OK):
                logger.error("Cannot read file (permission denied): %s", file_path)
                return False

            # Create a new file handler with explicit error handling
            try:
                self.file_handler = VirtualFileAccess(file_path, read_only)
                self.file_path = file_path
            except Exception as e:
                logger.error(f"Failed to create VirtualFileAccess: {e}", exc_info=True)
                return False

            # Verify we have data with explicit error handling
            try:
                file_size = self.file_handler.get_file_size()
                logger.info("File loaded, size=%s bytes", file_size)

                # Test read to verify file is readable
                test_data = self.file_handler.read(0, min(1024, file_size))
                if not test_data and file_size > 0:
                    logger.error("File appears to be unreadable - read test returned empty data for %s", file_path)
                else:
                    logger.debug(f"Read test successful: got {len(test_data)} bytes")
            except Exception as e:
                logger.error(f"Error reading file data: {e}", exc_info=True)
                return False

            if file_size == 0:
                logger.warning("Loaded file has zero size: %s", file_path)

            # Reset state
            self.current_offset = 0
            self.selection_start = -1
            self.selection_end = -1
            self.editing_offset = -1
            self.highlighter.clear_highlights()

            # Set up performance monitoring for large files
            self.performance_monitor.set_file_handler(self.file_handler)

            # Update UI with explicit repaints
            self.update_scrollbars()

            # Force immediate UI update
            logger.debug("Forcing viewport update")
            self.viewport().update()

            # Schedule multiple updates to ensure rendering
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(50, self.viewport().update)
            QTimer.singleShot(100, self.viewport().update)
            QTimer.singleShot(200, self.viewport().update)

            # Force layout update
            self.updateGeometry()

            # Update window title if this is a top-level window
            if self.window() and file_path:
                filename = os.path.basename(file_path)
                self.window().setWindowTitle(f"Hex Viewer - {filename}")

            logger.info("Loaded file: %s (%s bytes)", file_path, file_size)
            return True
        except Exception as e:
            logger.error("Error loading file: %s", e)
            if hasattr(self, 'file_handler') and self.file_handler:
                del self.file_handler
                self.file_handler = None
            return False

    def load_data(self, data: bytes, name: str = "Memory Buffer") -> bool:
        """
        Load binary data directly into the hex viewer.

        Args:
            data: Binary data to load
            name: Name for the data buffer

        Returns:
            True if the data was loaded successfully, False otherwise
        """
        try:
            # Log the data size being loaded
            logger.info(f"HexWidget.load_data: Loading {len(data)} bytes as '{name}'")

            if not data:
                logger.warning("Attempted to load empty data buffer")
                return False

            # Create a temporary file
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(data)
            temp_file.flush()  # Ensure data is written to disk
            temp_file_path = temp_file.name
            temp_file.close()

            # Load the temporary file
            logger.debug("Loading temporary file: %s", temp_file_path)
            result = self.load_file(temp_file_path, read_only=True)

            # Set the file path to indicate this is in-memory data
            self.file_path = name

            # Update window title if this is a top-level window
            if self.window():
                self.window().setWindowTitle(f"Hex Viewer - {name}")

            # Force an update of the viewport
            self.update()
            self.viewport().update()

            # Reset scrollbars to top
            self.verticalScrollBar().setValue(0)
            self.horizontalScrollBar().setValue(0)

            logger.info(f"Loaded data buffer: {name} ({len(data)} bytes), success={result}")
            return result
        except Exception as e:
            logger.error(f"Error loading data: {e}", exc_info=True)
            return False

    def close(self):
        """Close the current file and clean up resources."""
        if hasattr(self, 'file_handler') and self.file_handler:
            del self.file_handler
            self.file_handler = None

        self.file_path = ""
        self.current_offset = 0
        self.selection_start = -1
        self.selection_end = -1
        self.editing_offset = -1
        self.highlighter.clear_highlights()

        self.viewport().update()

        logger.debug("Closed hex viewer")

    def update_scrollbars(self):
        """Update scrollbar ranges based on current file size and viewport size."""
        if not self.file_handler:
            # No file loaded, disable scrollbars
            self.verticalScrollBar().setRange(0, 0)
            self.horizontalScrollBar().setRange(0, 0)
            return

        file_size = self.file_handler.get_file_size()

        # Calculate row count
        row_count = (file_size + self.bytes_per_row - 1) // self.bytes_per_row

        # Set vertical scrollbar range
        if row_count > 0:
            viewport_height = self.viewport().height() - self.header_height
            visible_rows = viewport_height // self.char_height
            max_scroll = max(0, row_count - visible_rows)
            self.verticalScrollBar().setRange(0, max_scroll)
            self.verticalScrollBar().setPageStep(visible_rows)
        else:
            self.verticalScrollBar().setRange(0, 0)

        # Set horizontal scrollbar range based on view mode
        if self.view_mode == ViewMode.HEX:
            # Calculate width based on bytes per row
            hex_width = self.address_width + self.gutter_width + self.bytes_per_row * 3 * self.char_width
            ascii_width = self.bytes_per_row * self.char_width
            total_width = hex_width + self.gutter_width * 2 + ascii_width

            viewport_width = self.viewport().width()
            if total_width > viewport_width:
                self.horizontalScrollBar().setRange(0, total_width - viewport_width)
                self.horizontalScrollBar().setPageStep(viewport_width // 2)
            else:
                self.horizontalScrollBar().setRange(0, 0)
        elif self.view_mode == ViewMode.BINARY:
            # Binary view needs more horizontal space
            binary_width = self.address_width + self.gutter_width + self.bytes_per_row * 9 * self.char_width

            viewport_width = self.viewport().width()
            if binary_width > viewport_width:
                self.horizontalScrollBar().setRange(0, binary_width - viewport_width)
                self.horizontalScrollBar().setPageStep(viewport_width // 2)
            else:
                self.horizontalScrollBar().setRange(0, 0)
        else:
            # Default for other view modes
            self.horizontalScrollBar().setRange(0, 0)

    def handle_scroll(self, value: int):
        """Handle scrollbar value changes."""
        if not self.file_handler:
            return

        # Calculate the new offset
        self.current_offset = value * self.bytes_per_row

        # Update the viewport
        self.viewport().update()

        # Emit signal
        self.offset_changed.emit(self.current_offset)

    def paintEvent(self, event: QPaintEvent):
        """Handle paint events for the viewport."""
        # This is handled by viewportPaintEvent
        super().paintEvent(event)

    def viewportEvent(self, event):
        """Handle viewport events."""
        if event.type() == event.Paint:
            self.viewportPaintEvent(QPaintEvent(event.region().boundingRect()))
            return True
        return super().viewportEvent(event)

    def viewportPaintEvent(self, event: QPaintEvent):
        """Paint the hex view to the viewport."""
        # Create painter
        painter = QPainter(self.viewport())

        # Default background
        painter.fillRect(event.rect(), self.bg_color)

        if not self.file_handler:
            # No file loaded, just show message
            painter.setPen(self.text_color)
            painter.drawText(10, 20, "No file loaded")
            return

        # Set font and ensure it's applied
        painter.setFont(self.font())

        # Add a border around the viewport for debugging
        painter.setPen(Qt.darkGray)
        painter.drawRect(0, 0, self.viewport().width()-1, self.viewport().height()-1)

        # Display debug info at the top
        file_size = self.file_handler.get_file_size()
        debug_text = f"File: {self.file_path} | Size: {file_size} bytes"
        painter.setPen(Qt.blue)
        painter.drawText(10, 15, debug_text)

        # Calculate visible region
        start_row = self.verticalScrollBar().value()
        viewport_height = self.viewport().height()
        visible_rows = (viewport_height - self.header_height) // self.char_height + 1

        h_scroll = self.horizontalScrollBar().value()

        # Show scrollbar values for debugging
        scroll_debug = f"Scroll: v={start_row}, h={h_scroll} | Rows: {visible_rows}"
        painter.drawText(10, 30, scroll_debug)

        # Calculate offset and size to read with safety checks
        start_offset = start_row * self.bytes_per_row

        # Safe calculation of end row and offset
        if file_size <= 0:
            # Handle empty file
            painter.setPen(Qt.red)
            painter.drawText(20, 60, "Empty file (0 bytes)")
            return

        # Calculate rows and offsets safely
        try:
            end_row = min(start_row + visible_rows, (file_size + self.bytes_per_row - 1) // self.bytes_per_row)
            end_offset = min(end_row * self.bytes_per_row, file_size)
            size = end_offset - start_offset

            # Show offset debug info
            offset_debug = f"Offset: {start_offset}-{end_offset} | Size: {size}"
            painter.drawText(10, 45, offset_debug)

            if size <= 0:
                painter.setPen(Qt.red)
                painter.drawText(20, 75, f"Invalid read size: {size} (rows {start_row}-{end_row})")
                return
        except Exception as calc_error:
            painter.setPen(Qt.red)
            painter.drawText(20, 60, f"Calculation error: {str(calc_error)}")
            return

        # Read data with detailed error handling
        try:
            # Read the visible data
            logger.info("Reading data: offset=%s, size=%s", start_offset, size)
            data = self.file_handler.read(start_offset, size)

            # Verify we got data
            if not data:
                msg = f"No data read at offset {start_offset}, size {size}"
                logger.warning(msg)
                painter.setPen(Qt.red)
                painter.drawText(20, 90, msg)
                return

            data_debug = f"Read: {len(data)} bytes | First bytes: {data[:8].hex(' ')}"
            painter.setPen(Qt.green)
            painter.drawText(10, 60, data_debug)
        except Exception as e:
            logger.error(f"Exception reading data: {e}", exc_info=True)
            painter.setPen(Qt.red)
            painter.drawText(20, 90, f"Error reading data: {str(e)}")
            return

        # Now continue with actual rendering
        # Draw a test pattern to verify rendering is happening
        painter.setPen(Qt.red)
        painter.drawRect(10, 100, 100, 100)
        painter.drawText(20, 120, "TEST PATTERN")

        # Continue with usual rendering if we got this far
        try:
            # Draw header
            self.draw_header(painter, h_scroll)

            # Calculate ASCII column position
            if self.view_mode == ViewMode.HEX:
                bytes_text_width = self.bytes_per_row * 3 * self.char_width
                self.ascii_offset_x = self.hex_offset_x + bytes_text_width + self.gutter_width

            # Adjust for horizontal scroll
            painter.translate(-h_scroll, 0)
        except Exception as e:
            logger.error("Error in header rendering: %s", e)
            return

        # Draw rows within a separate try block
        try:
            y = self.header_height
            for row in range(start_row, end_row):
                # Calculate row offset and size
                row_offset = row * self.bytes_per_row
                row_size = min(self.bytes_per_row, end_offset - row_offset)
                if row_size <= 0:
                    break

                # Get data for this row - add safety checks
                try:
                    start_idx = row_offset - start_offset
                    if start_idx < 0 or start_idx >= len(data):
                        logger.warning(f"Invalid row data index: {start_idx}, data length: {len(data)}")
                        continue

                    row_data = data[start_idx:start_idx + row_size]
                    if not row_data:
                        logger.warning("Empty row data at offset %s", row_offset)
                        continue

                    # Log the data being rendered
                    logger.debug(f"Rendering row at offset {row_offset}: {len(row_data)} bytes")


                    # Draw the row
                    if self.view_mode == ViewMode.HEX:
                        self.draw_hex_row(painter, row_data, row_offset, y)
                    elif self.view_mode == ViewMode.DECIMAL:
                        self.draw_decimal_row(painter, row_data, row_offset, y)
                    elif self.view_mode == ViewMode.BINARY:
                        self.draw_binary_row(painter, row_data, row_offset, y)
                except Exception as e:
                    logger.error("Error rendering row at offset %s: %s", row_offset, e)
                    # Draw error indicator
                    painter.setPen(Qt.red)
                    painter.drawText(10, y, f"Error: {str(e)[:30]}...")

                y += self.char_height
        except Exception as e:
            logger.error("Error in row rendering loop: %s", e)
            # Draw a final error indicator at the top
            painter.setPen(Qt.red)
            painter.drawText(10, 80, f"Error in rendering: {str(e)[:50]}...")

    def draw_header(self, painter: QPainter, h_scroll: int):
        """Draw the header with column labels."""
        # Draw header background
        header_rect = QRect(0, 0, self.viewport().width() + h_scroll, self.header_height)
        painter.fillRect(header_rect, self.header_bg_color)

        # Set text color
        painter.setPen(self.header_text_color)

        # EMERGENCY FIX: Draw address header with maximum visibility
        address_header_rect = QRect(0, 0, self.address_width, self.header_height)

        # Draw white background for header
        painter.fillRect(address_header_rect, QColor(255, 255, 255))

        # Draw bold black text on white background
        painter.setPen(QPen(QColor(0, 0, 0), 2, Qt.SolidLine))
        painter.setFont(QFont("Arial", 12, QFont.Bold))
        painter.drawText(address_header_rect, Qt.AlignCenter | Qt.TextDontClip, "OFFSET")

        # Draw a border around the header
        painter.setPen(QPen(QColor(255, 0, 0), 1, Qt.SolidLine))
        painter.drawRect(address_header_rect)

        # Draw separator line with stronger visibility
        painter.setPen(QPen(Qt.darkGray, 1, Qt.SolidLine))
        painter.drawLine(self.address_width, 0, self.address_width, self.header_height)

        # Draw data column headers based on view mode
        if self.view_mode == ViewMode.HEX:
            # EMERGENCY FIX: Draw hex column headers with maximum visibility
            x = self.hex_offset_x
            for i in range(self.bytes_per_row):
                header_text = f"{i:X}"
                header_rect = QRect(x + i * 3 * self.char_width, 0,
                                    2 * self.char_width, self.header_height)

                # Draw white background for each header cell
                painter.fillRect(header_rect, QColor(255, 255, 255))

                # Draw bold black text
                painter.setPen(QPen(QColor(0, 0, 0), 2, Qt.SolidLine))
                painter.setFont(QFont("Arial", 11, QFont.Bold))
                painter.drawText(header_rect, Qt.AlignCenter | Qt.TextDontClip, header_text)

                # Draw colored border around cell
                painter.setPen(QPen(QColor(0, 128, 0), 1, Qt.SolidLine))
                painter.drawRect(header_rect)

            # EMERGENCY FIX: Draw ASCII column header with maximum visibility
            ascii_header_rect = QRect(self.ascii_offset_x, 0,
                                     self.bytes_per_row * self.char_width, self.header_height)

            # Draw white background
            painter.fillRect(ascii_header_rect, QColor(255, 255, 255))

            # Draw bold black text
            painter.setPen(QPen(QColor(0, 0, 0), 2, Qt.SolidLine))
            painter.setFont(QFont("Arial", 12, QFont.Bold))
            painter.drawText(ascii_header_rect, Qt.AlignCenter | Qt.TextDontClip, "ASCII")

            # Draw colored border
            painter.setPen(QPen(QColor(128, 0, 128), 1, Qt.SolidLine))
            painter.drawRect(ascii_header_rect)

        elif self.view_mode == ViewMode.DECIMAL:
            # Draw decimal column headers
            x = self.hex_offset_x
            for i in range(self.bytes_per_row):
                header_text = f"{i}"
                header_rect = QRect(x + i * 4 * self.char_width, 0,
                                    3 * self.char_width, self.header_height)
                painter.drawText(header_rect, Qt.AlignCenter, header_text)

        elif self.view_mode == ViewMode.BINARY:
            # Draw binary column headers
            x = self.hex_offset_x
            for i in range(min(self.bytes_per_row, 8)):  # Limit to 8 bytes per row for binary view
                header_text = f"{i}"
                header_rect = QRect(x + i * 9 * self.char_width, 0,
                                    8 * self.char_width, self.header_height)
                painter.drawText(header_rect, Qt.AlignCenter, header_text)

        # Draw bottom border
        painter.drawLine(0, self.header_height - 1,
                         self.viewport().width() + h_scroll, self.header_height - 1)

    def draw_hex_row(self, painter: QPainter, data: bytes, offset: int, y: int):
        """Draw a row in hex view mode."""
        try:
            # Add debug logging
            if not data:
                logger.warning("Empty data passed to draw_hex_row at offset %s", offset)

            # Force QT to show the widget is active and receiving paint events
            logger.debug(f"Drawing hex row at y={y}, offset={offset:X}, data_len={len(data)}")

            # EMERGENCY FIX: Draw address with white background and black text
            addr_rect = QRect(0, y, self.address_width, self.char_height)

            # Fill with white background
            painter.fillRect(addr_rect, QColor(255, 255, 255))

            # Add prominent border
            painter.setPen(QPen(QColor(0, 0, 255), 1, Qt.SolidLine))
            painter.drawRect(addr_rect)

            # Draw text with maximum contrast - black on white
            painter.setPen(QPen(QColor(0, 0, 0), 2, Qt.SolidLine))
            painter.setFont(QFont("Courier New", 12, QFont.Bold))

            # Draw the address text with clear margins
            addr_text_rect = addr_rect.adjusted(5, 0, -5, 0)
            painter.drawText(addr_text_rect, Qt.AlignRight | Qt.AlignVCenter | Qt.TextDontClip, f"{offset:08X}")

            # Draw separator with better visibility
            painter.setPen(QPen(Qt.darkGray, 1, Qt.SolidLine))
            painter.drawLine(self.address_width, y, self.address_width, y + self.char_height)

            # Get highlights for this row
            row_end = offset + len(data)
            highlights = self.highlighter.get_highlights_for_region(offset, row_end)
        except Exception as e:
            logger.error("Exception in draw_hex_row setup: %s", e)
            painter.setPen(Qt.red)
            painter.drawText(10, y, f"Error in hex row: {str(e)[:30]}...")
            return

        # Draw hex values
        x = self.hex_offset_x
        for i, b in enumerate(data):
            byte_offset = offset + i

            # Draw selection and highlights
            self.draw_byte_highlights(painter, byte_offset, x, y, 3 * self.char_width, highlights)

            # EMERGENCY FIX: Draw hex values with forced white background and black text
            byte_rect = QRect(x, y, 2 * self.char_width, self.char_height)

            # Draw white background rect
            painter.fillRect(byte_rect, QColor(255, 255, 255))

            # Draw text in black, ignoring theme colors completely
            painter.setPen(QPen(QColor(0, 0, 0), 2))
            painter.setFont(QFont("Courier New", 12, QFont.Bold))

            # Draw the hex text
            painter.drawText(byte_rect, Qt.AlignCenter | Qt.TextDontClip, f"{b:02X}")

            # Draw red border around the text area
            painter.setPen(QPen(QColor(255, 0, 0), 1))
            painter.drawRect(byte_rect)

            x += 3 * self.char_width  # 2 chars + space

        # Draw ASCII representation
        x = self.ascii_offset_x
        for i, b in enumerate(data):
            byte_offset = offset + i

            # Draw selection and highlights
            self.draw_byte_highlights(painter, byte_offset, x, y, self.char_width, highlights)

            # EMERGENCY FIX: Draw ASCII character with forced white background and black text
            char_rect = QRect(x, y, self.char_width, self.char_height)
            c = chr(b) if 32 <= b <= 126 else "."

            # Draw white background rect
            painter.fillRect(char_rect, QColor(255, 255, 255))

            # Draw text in black, ignoring theme colors
            painter.setPen(QPen(QColor(0, 0, 0), 2))
            painter.setFont(QFont("Courier New", 12, QFont.Bold))

            # Draw text with explicit alignment and formatting
            painter.drawText(char_rect, Qt.AlignCenter | Qt.TextDontClip, c)

            # Draw border around character area
            painter.setPen(QPen(QColor(0, 0, 255), 1))
            painter.drawRect(char_rect)

            x += self.char_width

    def draw_decimal_row(self, painter: QPainter, data: bytes, offset: int, y: int):
        """Draw a row in decimal view mode."""
        # Draw row address
        addr_rect = QRect(0, y, self.address_width, self.char_height)
        painter.fillRect(addr_rect, self.address_bg_color)
        painter.setPen(self.address_text_color)
        painter.drawText(addr_rect, Qt.AlignRight | Qt.AlignVCenter, f"{offset:08d}")

        # Draw separator
        painter.setPen(self.address_bg_color.darker(120))
        painter.drawLine(self.address_width, y, self.address_width, y + self.char_height)

        # Get highlights for this row
        row_end = offset + len(data)
        highlights = self.highlighter.get_highlights_for_region(offset, row_end)

        # Draw decimal values
        x = self.hex_offset_x
        for i, b in enumerate(data):
            byte_offset = offset + i

            # Draw selection and highlights
            self.draw_byte_highlights(painter, byte_offset, x, y, 4 * self.char_width, highlights)

            # Draw decimal value
            painter.setPen(self.text_color)
            byte_rect = QRect(x, y, 3 * self.char_width, self.char_height)
            painter.drawText(byte_rect, Qt.AlignRight, f"{b:3d}")

            x += 4 * self.char_width  # 3 chars + space

    def draw_binary_row(self, painter: QPainter, data: bytes, offset: int, y: int):
        """Draw a row in binary view mode."""
        # Draw row address
        addr_rect = QRect(0, y, self.address_width, self.char_height)
        painter.fillRect(addr_rect, self.address_bg_color)
        painter.setPen(self.address_text_color)
        painter.drawText(addr_rect, Qt.AlignRight | Qt.AlignVCenter, f"{offset:08X}")

        # Draw separator
        painter.setPen(self.address_bg_color.darker(120))
        painter.drawLine(self.address_width, y, self.address_width, y + self.char_height)

        # Get highlights for this row
        row_end = offset + len(data)
        highlights = self.highlighter.get_highlights_for_region(offset, row_end)

        # Draw binary values
        x = self.hex_offset_x
        for i, b in enumerate(data):
            byte_offset = offset + i

            # Draw selection and highlights
            self.draw_byte_highlights(painter, byte_offset, x, y, 9 * self.char_width, highlights)

            # Draw binary value
            painter.setPen(self.text_color)
            byte_rect = QRect(x, y, 8 * self.char_width, self.char_height)
            painter.drawText(byte_rect, Qt.AlignCenter, f"{b:08b}")

            x += 9 * self.char_width  # 8 chars + space

    def draw_byte_highlights(self, painter: QPainter, byte_offset: int, x: int, y: int,
                            width: int, highlights: List[HexHighlight]):
        """Draw highlights for a specific byte."""
        # Check if the byte is selected
        is_selected = (self.selection_start >= 0 and
                      self.selection_end >= 0 and
                      self.selection_start <= byte_offset < self.selection_end)

        if is_selected:
            # Draw selection highlight
            select_rect = QRect(x, y, width, self.char_height)
            painter.fillRect(select_rect, self.selection_color)

        # Draw other highlights
        for highlight in sorted(highlights, key=lambda h: h.highlight_type.value):
            if highlight.contains(byte_offset):
                # Skip if this is just the selection highlight
                if highlight.highlight_type == HighlightType.SELECTION:
                    continue

                # Get the highlight color
                r, g, b, a = highlight.get_rgba()
                highlight_color = QColor(r, g, b, a)

                # Draw the highlight
                highlight_rect = QRect(x, y, width, self.char_height)
                painter.fillRect(highlight_rect, highlight_color)

    def set_view_mode(self, mode: ViewMode):
        """
        Set the current view mode.

        Args:
            mode: The new view mode
        """
        if mode != self.view_mode:
            self.view_mode = mode
            self.update_scrollbars()
            self.viewport().update()
            self.view_mode_changed.emit(mode)

    def set_bytes_per_row(self, bytes_per_row: int):
        """
        Set the number of bytes per row.

        Args:
            bytes_per_row: Number of bytes to display per row
        """
        if bytes_per_row != self.bytes_per_row and bytes_per_row > 0:
            self.bytes_per_row = bytes_per_row
            self.renderer.set_bytes_per_row(bytes_per_row)
            self.update_scrollbars()
            self.viewport().update()

    def set_group_size(self, group_size: int):
        """
        Set the group size for byte grouping.

        Args:
            group_size: Number of bytes to group together (1, 2, 4, or 8)
        """
        if group_size != self.group_size and group_size in (1, 2, 4, 8):
            self.group_size = group_size
            self.renderer.set_group_size(group_size)
            self.viewport().update()

    def jump_to_offset(self, offset: int):
        """
        Jump to a specific offset in the file.

        Args:
            offset: Offset to jump to
        """
        if not self.file_handler:
            return

        # Ensure offset is within file bounds
        file_size = self.file_handler.get_file_size()
        offset = max(0, min(offset, file_size - 1))

        # Calculate row for this offset
        row = offset // self.bytes_per_row

        # Set vertical scrollbar value
        self.verticalScrollBar().setValue(row)

        # Update current offset
        self.current_offset = row * self.bytes_per_row

        # Update selection to point at the offset
        self.selection_start = offset
        self.selection_end = offset + 1

        # Update the viewport
        self.viewport().update()

        # Emit signals
        self.offset_changed.emit(self.current_offset)
        self.selection_changed.emit(self.selection_start, self.selection_end)

    def select_range(self, start: int, end: int):
        """
        Select a range of bytes.

        Args:
            start: Starting offset
            end: Ending offset (exclusive)
        """
        if not self.file_handler:
            return

        # Ensure offsets are within file bounds
        file_size = self.file_handler.get_file_size()
        start = max(0, min(start, file_size - 1))
        end = max(start + 1, min(end, file_size))

        # Set selection
        self.selection_start = start
        self.selection_end = end

        # Make sure the selection is visible
        self.jump_to_offset(start)

        # Add selection highlight
        self.highlighter.clear_highlights(HighlightType.SELECTION)
        self.highlighter.add_highlight(
            start=start,
            end=end,
            highlight_type=HighlightType.SELECTION,
            color="#0078D7",
            alpha=0.3
        )

        # Update the viewport
        self.viewport().update()

        # Emit signal
        self.selection_changed.emit(start, end)

    def clear_selection(self):
        """Clear the current selection."""
        if self.selection_start >= 0 and self.selection_end >= 0:
            self.selection_start = -1
            self.selection_end = -1
            self.highlighter.clear_highlights(HighlightType.SELECTION)
            self.viewport().update()
            self.selection_changed.emit(-1, -1)

    def get_selection(self) -> Tuple[int, int]:
        """
        Get the current selection range.

        Returns:
            Tuple of (start, end) offsets, or (-1, -1) if no selection
        """
        return (self.selection_start, self.selection_end)

    def get_selected_data(self) -> Optional[bytes]:
        """
        Get the selected data.

        Returns:
            Selected data as bytes, or None if no selection
        """
        if not self.file_handler or self.selection_start < 0 or self.selection_end <= self.selection_start:
            return None

        size = self.selection_end - self.selection_start
        return self.file_handler.read(self.selection_start, size)

    def add_bookmark(self, offset: int = None, size: int = 1, description: str = ""):
        """
        Add a bookmark at the specified offset or current selection.

        Args:
            offset: Offset to bookmark, or None to use current selection
            size: Size of the bookmarked region
            description: Description of the bookmark
        """
        if not self.file_handler:
            return

        if offset is None:
            if self.selection_start >= 0 and self.selection_end > self.selection_start:
                offset = self.selection_start
                size = self.selection_end - self.selection_start
            else:
                offset = self.current_offset

        self.highlighter.add_bookmark(offset, size, description)
        self.viewport().update()

    def search(self, pattern: Union[bytes, str], start_offset: int = 0,
              case_sensitive: bool = True, direction: str = "forward") -> Optional[int]:
        """
        Search for a pattern in the file.

        Args:
            pattern: Search pattern (bytes or string)
            start_offset: Offset to start searching from
            case_sensitive: Whether to perform case-sensitive search
            direction: Search direction ("forward" or "backward")

        Returns:
            Offset of the first match, or None if not found
        """
        if not self.file_handler:
            return None

        # Ensure pattern is bytes
        if isinstance(pattern, str):
            try:
                # Try to decode as hex string
                pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
            except ValueError:
                # Treat as regular string
                pattern_bytes = pattern.encode('utf-8')
        else:
            pattern_bytes = pattern

        file_size = self.file_handler.get_file_size()

        if direction == "forward":
            # Forward search
            chunk_size = 1024 * 1024  # 1 MB chunks
            offset = start_offset

            while offset < file_size:
                # Read a chunk
                size = min(chunk_size, file_size - offset)
                chunk = self.file_handler.read(offset, size)

                # If not case sensitive, convert both to lowercase for comparison
                if not case_sensitive and isinstance(pattern, str):
                    # Only for string patterns
                    search_chunk = chunk.lower()
                    search_pattern = pattern_bytes.lower()
                else:
                    search_chunk = chunk
                    search_pattern = pattern_bytes

                # Search in the chunk
                pos = search_chunk.find(search_pattern)
                if pos >= 0:
                    # Found a match
                    match_offset = offset + pos

                    # Highlight the match
                    self.highlighter.add_search_result(
                        match_offset, match_offset + len(pattern_bytes),
                        query=pattern if isinstance(pattern, str) else pattern_bytes.hex(' ')
                    )

                    # Select the match
                    self.select_range(match_offset, match_offset + len(pattern_bytes))

                    return match_offset

                # Move to the next chunk, overlapping by pattern length - 1
                offset += max(1, size - (len(pattern_bytes) - 1))
        else:
            # Backward search
            chunk_size = 1024 * 1024  # 1 MB chunks

            # Start at the specified offset, or file end if beyond bounds
            offset = min(start_offset, file_size)

            while offset > 0:
                # Calculate chunk start and size
                chunk_start = max(0, offset - chunk_size)
                size = offset - chunk_start

                # Read the chunk
                chunk = self.file_handler.read(chunk_start, size)

                # If not case sensitive, convert both to lowercase for comparison
                if not case_sensitive and isinstance(pattern, str):
                    search_chunk = chunk.lower()
                    search_pattern = pattern_bytes.lower()
                else:
                    search_chunk = chunk
                    search_pattern = pattern_bytes

                # Search in the chunk from right to left
                pos = search_chunk.rfind(search_pattern)
                if pos >= 0:
                    # Found a match
                    match_offset = chunk_start + pos

                    # Highlight the match
                    self.highlighter.add_search_result(
                        match_offset, match_offset + len(pattern_bytes),
                        query=pattern if isinstance(pattern, str) else pattern_bytes.hex(' ')
                    )

                    # Select the match
                    self.select_range(match_offset, match_offset + len(pattern_bytes))

                    return match_offset

                # Move to the next chunk, ensuring we don't miss any potential matches
                offset = chunk_start

        # No match found
        return None

    def edit_byte(self, offset: int, value: int):
        """
        Edit a single byte at the specified offset.

        Args:
            offset: Offset of the byte to edit
            value: New byte value (0-255)
        """
        if not self.file_handler or self.file_handler.read_only:
            return False

        # Ensure offset is within file bounds
        file_size = self.file_handler.get_file_size()
        if offset < 0 or offset >= file_size:
            return False

        # Ensure value is a valid byte
        value = max(0, min(value, 255))

        # Write the byte
        result = self.file_handler.write(offset, bytes([value]))

        if result:
            # Add highlight for the edited byte
            self.highlighter.add_modification_highlight(offset, offset + 1)

            # Update the viewport
            self.viewport().update()

            # Emit signal
            self.data_changed.emit(offset, 1)

        return result

    def edit_selection(self, data: bytes):
        """
        Replace the selected data with new data.

        Args:
            data: New data to write
        """
        if (not self.file_handler or self.file_handler.read_only or
            self.selection_start < 0 or self.selection_end <= self.selection_start):
            return False

        # Ensure the new data is the same size as the selection
        selection_size = self.selection_end - self.selection_start
        if len(data) != selection_size:
            return False

        # Write the data
        result = self.file_handler.write(self.selection_start, data)

        if result:
            # Add highlight for the edited region
            self.highlighter.add_modification_highlight(self.selection_start, self.selection_end)

            # Update the viewport
            self.viewport().update()

            # Emit signal
            self.data_changed.emit(self.selection_start, selection_size)

        return result

    def apply_edits(self):
        """Apply all pending edits to the file."""
        if not self.file_handler or self.file_handler.read_only:
            return False

        return self.file_handler.apply_edits()

    def discard_edits(self):
        """Discard all pending edits."""
        if not self.file_handler:
            return

        self.file_handler.discard_edits()

        # Clear modification highlights
        self.highlighter.clear_highlights(HighlightType.MODIFICATION)

        # Update the viewport
        self.viewport().update()

    def show_context_menu(self, pos: QPoint):
        """Show the context menu."""
        if not self.file_handler:
            return

        menu = QMenu(self)

        # Jump to offset action
        jump_action = menu.addAction("Jump to Offset...")
        jump_action.triggered.connect(self.show_jump_dialog)

        menu.addSeparator()

        # View mode submenu
        view_mode_menu = menu.addMenu("View Mode")
        for mode in ViewMode:
            action = view_mode_menu.addAction(mode.name.capitalize())
            action.setCheckable(True)
            action.setChecked(mode == self.view_mode)
            action.triggered.connect(lambda checked, m=mode: self.set_view_mode(m))

        # Bytes per row submenu
        bytes_row_menu = menu.addMenu("Bytes per Row")
        for bpr in [8, 16, 24, 32, 64]:
            action = bytes_row_menu.addAction(str(bpr))
            action.setCheckable(True)
            action.setChecked(bpr == self.bytes_per_row)
            action.triggered.connect(lambda checked, b=bpr: self.set_bytes_per_row(b))

        # Grouping submenu
        group_menu = menu.addMenu("Byte Grouping")
        for gs in [1, 2, 4, 8]:
            action = group_menu.addAction(str(gs))
            action.setCheckable(True)
            action.setChecked(gs == self.group_size)
            action.triggered.connect(lambda checked, g=gs: self.set_group_size(g))

        menu.addSeparator()

        # Selection-dependent actions
        has_selection = self.selection_start >= 0 and self.selection_end > self.selection_start

        # Copy actions
        copy_menu = menu.addMenu("Copy")
        copy_menu.setEnabled(has_selection)

        if has_selection:
            copy_hex_action = copy_menu.addAction("Copy as Hex")
            copy_hex_action.triggered.connect(self.copy_selection_as_hex)

            copy_text_action = copy_menu.addAction("Copy as Text")
            copy_text_action.triggered.connect(self.copy_selection_as_text)

            copy_c_array_action = copy_menu.addAction("Copy as C Array")
            copy_c_array_action.triggered.connect(self.copy_selection_as_c_array)

        # Edit actions
        edit_menu = menu.addMenu("Edit")
        edit_menu.setEnabled(not self.file_handler.read_only and has_selection)

        if not self.file_handler.read_only and has_selection:
            fill_action = edit_menu.addAction("Fill Selection...")
            fill_action.triggered.connect(self.fill_selection)

            edit_action = edit_menu.addAction("Edit Selection...")
            edit_action.triggered.connect(self.edit_selection_dialog)

        menu.addSeparator()

        # Bookmark action
        bookmark_action = menu.addAction("Add Bookmark...")
        bookmark_action.triggered.connect(lambda: self.add_bookmark_dialog())

        # Search action
        search_action = menu.addAction("Search...")
        search_action.triggered.connect(self.show_search_dialog)

        menu.addSeparator()

        # Apply/discard edits
        if not self.file_handler.read_only:
            apply_action = menu.addAction("Apply Edits")
            apply_action.triggered.connect(self.apply_edits)

            discard_action = menu.addAction("Discard Edits")
            discard_action.triggered.connect(self.discard_edits)

        # Show the menu
        menu.exec_(self.mapToGlobal(pos))

    def show_jump_dialog(self):
        """Show dialog for jumping to a specific offset."""
        if not self.file_handler:
            return

        offset_str, ok = QInputDialog.getText(
            self, "Jump to Offset", "Enter offset (decimal or 0x... for hex):",
            text=f"0x{self.current_offset:X}"
        )

        if ok and offset_str:
            try:
                # Parse the offset
                if offset_str.startswith("0x"):
                    offset = int(offset_str[2:], 16)
                else:
                    offset = int(offset_str)

                # Jump to the offset
                self.jump_to_offset(offset)
            except ValueError:
                QMessageBox.warning(self, "Invalid Offset",
                                   "Please enter a valid offset in decimal or hex (0x...) format.")

    def show_search_dialog(self):
        """Show dialog for searching for a pattern."""
        if not self.file_handler:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Search")
        dialog.setMinimumWidth(400)

        # Create layout
        layout = QVBoxLayout(dialog)

        # Pattern input
        form_layout = QFormLayout()
        pattern_edit = QLineEdit()
        form_layout.addRow("Search pattern:", pattern_edit)

        # Search type
        search_type_combo = QComboBox()
        search_type_combo.addItems(["Hex", "Text", "ASCII"])
        form_layout.addRow("Search type:", search_type_combo)

        # Case sensitivity
        case_check = QCheckBox("Case sensitive")
        case_check.setChecked(True)
        form_layout.addRow("", case_check)

        # Direction
        direction_combo = QComboBox()
        direction_combo.addItems(["Forward", "Backward"])
        form_layout.addRow("Direction:", direction_combo)

        layout.addLayout(form_layout)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        # Show dialog
        if dialog.exec_() == QDialog.Accepted:
            pattern = pattern_edit.text()
            search_type = search_type_combo.currentText().lower()
            case_sensitive = case_check.isChecked()
            direction = direction_combo.currentText().lower()

            if not pattern:
                return

            # Convert pattern based on search type
            if search_type == "hex":
                try:
                    pattern_bytes = bytes.fromhex(pattern.replace(" ", ""))
                except ValueError:
                    QMessageBox.warning(self, "Invalid Hex Pattern",
                                       "Please enter a valid hex pattern (e.g., 'FF 00 AB').")
                    return
            else:  # Text or ASCII
                pattern_bytes = pattern.encode('utf-8')

            # Start search from current selection or offset
            if self.selection_end > self.selection_start:
                start_offset = self.selection_end if direction == "forward" else self.selection_start
            else:
                start_offset = self.current_offset

            # Perform search
            result = self.search(pattern_bytes, start_offset, case_sensitive, direction)

            if result is None:
                QMessageBox.information(self, "Search Result",
                                       f"Pattern '{pattern}' not found.")

    def add_bookmark_dialog(self):
        """Show dialog for adding a bookmark."""
        if not self.file_handler:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Add Bookmark")

        # Create layout
        layout = QVBoxLayout(dialog)

        # Offset and size inputs
        form_layout = QFormLayout()

        # Default to current selection or offset
        if self.selection_start >= 0 and self.selection_end > self.selection_start:
            default_offset = self.selection_start
            default_size = self.selection_end - self.selection_start
        else:
            default_offset = self.current_offset
            default_size = 1

        offset_edit = QLineEdit(f"0x{default_offset:X}")
        form_layout.addRow("Offset:", offset_edit)

        size_spin = QSpinBox()
        size_spin.setRange(1, 1024)
        size_spin.setValue(default_size)
        form_layout.addRow("Size:", size_spin)

        description_edit = QLineEdit()
        form_layout.addRow("Description:", description_edit)

        layout.addLayout(form_layout)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        # Show dialog
        if dialog.exec_() == QDialog.Accepted:
            offset_text = offset_edit.text()
            size = size_spin.value()
            description = description_edit.text()

            try:
                # Parse the offset
                if offset_text.startswith("0x"):
                    offset = int(offset_text[2:], 16)
                else:
                    offset = int(offset_text)

                # Add the bookmark
                self.add_bookmark(offset, size, description)
            except ValueError:
                QMessageBox.warning(self, "Invalid Offset",
                                   "Please enter a valid offset in decimal or hex (0x...) format.")

    def copy_selection_as_hex(self):
        """Copy the selected data as a hex string."""
        data = self.get_selected_data()
        if not data:
            return

        # Format as hex string
        hex_str = " ".join(f"{b:02X}" for b in data)

        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(hex_str)

    def copy_selection_as_text(self):
        """Copy the selected data as text."""
        data = self.get_selected_data()
        if not data:
            return

        # Try to decode as UTF-8, falling back to escaped string
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            # Fall back to printable ASCII
            text = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02X}" for b in data)

        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def copy_selection_as_c_array(self):
        """Copy the selected data as a C array initializer."""
        data = self.get_selected_data()
        if not data:
            return

        # Format as C array
        hex_values = [f"0x{b:02X}" for b in data]
        array_str = "unsigned char data[] = {\n    "
        array_str += ",\n    ".join(", ".join(hex_values[i:i+8]) for i in range(0, len(hex_values), 8))
        array_str += "\n};"

        # Add length define
        array_str = f"#define DATA_LENGTH {len(data)}\n\n" + array_str

        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(array_str)

    def fill_selection(self):
        """Fill the selected range with a repeated value."""
        if (not self.file_handler or self.file_handler.read_only or
            self.selection_start < 0 or self.selection_end <= self.selection_start):
            return

        # Get fill value
        value_str, ok = QInputDialog.getText(
            self, "Fill Selection", "Enter fill value (decimal or 0x... for hex):",
            text="0x00"
        )

        if ok and value_str:
            try:
                # Parse the value
                if value_str.startswith("0x"):
                    value = int(value_str[2:], 16)
                else:
                    value = int(value_str)

                # Ensure it's a valid byte
                value = max(0, min(value, 255))

                # Create fill data
                size = self.selection_end - self.selection_start
                fill_data = bytes([value] * size)

                # Write the data
                self.edit_selection(fill_data)
            except ValueError:
                QMessageBox.warning(self, "Invalid Value",
                                   "Please enter a valid byte value in decimal or hex (0x...) format.")

    def edit_selection_dialog(self):
        """Show dialog for editing the selected data."""
        if (not self.file_handler or self.file_handler.read_only or
            self.selection_start < 0 or self.selection_end <= self.selection_start):
            return

        # Get the selected data
        data = self.get_selected_data()
        if not data:
            return

        # Create a hex string representation
        hex_str = self.renderer.render_hex_view(data, self.selection_start)

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Selection")
        dialog.resize(600, 400)

        # Create layout
        layout = QVBoxLayout(dialog)

        # Instructions
        instruction_label = QLabel(
            "Edit the hex values. Maintain the same format with line numbers and ASCII representation."
        )
        layout.addWidget(instruction_label)

        # Text edit for hex data
        text_edit = QPlainTextEdit()
        text_edit.setFont(self.font())
        text_edit.setPlainText(hex_str)
        layout.addWidget(text_edit)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        # Show dialog
        if dialog.exec_() == QDialog.Accepted:
            # Parse the edited text
            edited_text = text_edit.toPlainText()
            start_offset, edited_data = parse_hex_view(edited_text)

            # Check if the data size matches the selection
            if len(edited_data) != len(data):
                QMessageBox.warning(self, "Invalid Edit",
                                   f"Edited data size ({len(edited_data)}) does not match " +
                                   f"selection size ({len(data)}).")
                return

            # Apply the edit
            self.edit_selection(edited_data)

    def resizeEvent(self, event: QResizeEvent):
        """Handle resize events."""
        super().resizeEvent(event)
        self.update_scrollbars()

    def keyPressEvent(self, event: QKeyEvent):
        """Handle key press events."""
        if not self.file_handler:
            return super().keyPressEvent(event)

        key = event.key()
        modifiers = event.modifiers()

        if key == Qt.Key_G and modifiers & Qt.ControlModifier:
            # Ctrl+G: Jump to offset
            self.show_jump_dialog()
            event.accept()
            return

        if key == Qt.Key_F and modifiers & Qt.ControlModifier:
            # Ctrl+F: Search
            self.show_search_dialog()
            event.accept()
            return

        if key == Qt.Key_B and modifiers & Qt.ControlModifier:
            # Ctrl+B: Add bookmark
            self.add_bookmark_dialog()
            event.accept()
            return

        if key in (Qt.Key_Home, Qt.Key_End, Qt.Key_PageUp, Qt.Key_PageDown,
                  Qt.Key_Up, Qt.Key_Down, Qt.Key_Left, Qt.Key_Right):
            # Navigation keys
            self.handle_navigation_key(key, modifiers)
            event.accept()
            return

        # For other keys, fall back to parent implementation
        super().keyPressEvent(event)

    def handle_navigation_key(self, key: int, modifiers: Qt.KeyboardModifiers):
        """Handle navigation key events."""
        file_size = self.file_handler.get_file_size()

        if key == Qt.Key_Home:
            # Home: Jump to start of file
            self.jump_to_offset(0)
        elif key == Qt.Key_End:
            # End: Jump to end of file
            self.jump_to_offset(max(0, file_size - 1))
        elif key == Qt.Key_PageUp:
            # Page Up: Move up one page
            current_row = self.verticalScrollBar().value()
            page_size = self.verticalScrollBar().pageStep()
            new_row = max(0, current_row - page_size)
            self.verticalScrollBar().setValue(new_row)
        elif key == Qt.Key_PageDown:
            # Page Down: Move down one page
            current_row = self.verticalScrollBar().value()
            page_size = self.verticalScrollBar().pageStep()
            new_row = min(self.verticalScrollBar().maximum(), current_row + page_size)
            self.verticalScrollBar().setValue(new_row)
        elif key == Qt.Key_Up:
            # Up: Move up one row
            current_row = self.verticalScrollBar().value()
            new_row = max(0, current_row - 1)
            self.verticalScrollBar().setValue(new_row)
        elif key == Qt.Key_Down:
            # Down: Move down one row
            current_row = self.verticalScrollBar().value()
            new_row = min(self.verticalScrollBar().maximum(), current_row + 1)
            self.verticalScrollBar().setValue(new_row)
        elif key == Qt.Key_Left:
            # Left: Move to previous byte
            if self.selection_start > 0:
                self.select_range(self.selection_start - 1, self.selection_start)
            else:
                self.select_range(0, 1)
        elif key == Qt.Key_Right:
            # Right: Move to next byte
            if self.selection_start < file_size - 1:
                self.select_range(self.selection_start + 1, self.selection_start + 2)
            else:
                self.select_range(file_size - 1, file_size)

    def mousePressEvent(self, event: QMouseEvent):
        """Handle mouse press events."""
        if not self.file_handler or event.button() != Qt.LeftButton:
            return super().mousePressEvent(event)

        # Handle click in the hex view
        position = event.pos()
        if position.y() < self.header_height:
            # Click in header
            return

        # Calculate offset from click position
        byte_offset = self.get_offset_from_position(position)
        if byte_offset >= 0:
            # Select the clicked byte
            self.select_range(byte_offset, byte_offset + 1)

        # Accept the event
        event.accept()

    def mouseMoveEvent(self, event: QMouseEvent):
        """Handle mouse move events."""
        if not self.file_handler or not (event.buttons() & Qt.LeftButton):
            return super().mouseMoveEvent(event)

        # Handle drag in the hex view for selection
        if self.selection_start >= 0:
            position = event.pos()
            byte_offset = self.get_offset_from_position(position)

            if byte_offset >= 0:
                # Extend selection to include the dragged-to byte
                start = min(self.selection_start, byte_offset)
                end = max(self.selection_start, byte_offset + 1)
                self.select_range(start, end)

        # Accept the event
        event.accept()

    def get_offset_from_position(self, position: QPoint) -> int:
        """
        Get the byte offset from a position in the viewport.

        Args:
            position: Position in the viewport

        Returns:
            Byte offset, or -1 if not on a byte
        """
        if not self.file_handler:
            return -1

        # Check if the position is below the header
        if position.y() < self.header_height:
            return -1

        # Calculate row from y position
        row = (position.y() - self.header_height) // self.char_height
        row += self.verticalScrollBar().value()

        # Calculate horizontal scroll offset
        h_scroll = self.horizontalScrollBar().value()
        x = position.x() + h_scroll

        # Check if click is in the address column
        if x < self.address_width:
            return -1

        file_size = self.file_handler.get_file_size()
        row_offset = row * self.bytes_per_row

        if self.view_mode == ViewMode.HEX:
            # Check if click is in the hex part
            hex_width = self.bytes_per_row * 3 * self.char_width

            if x >= self.hex_offset_x and x < self.hex_offset_x + hex_width:
                # Calculate byte offset within the row
                rel_x = x - self.hex_offset_x
                col = rel_x // (3 * self.char_width)

                # Ensure col is within the row
                col = min(col, self.bytes_per_row - 1)

                # Calculate final offset
                offset = row_offset + col

                # Ensure the offset is within the file
                if offset < file_size:
                    return offset

            # Check if click is in the ASCII part
            if x >= self.ascii_offset_x:
                rel_x = x - self.ascii_offset_x
                col = rel_x // self.char_width

                # Ensure col is within the row
                col = min(col, self.bytes_per_row - 1)

                # Calculate final offset
                offset = row_offset + col

                # Ensure the offset is within the file
                if offset < file_size:
                    return offset
        elif self.view_mode == ViewMode.DECIMAL:
            # Check if click is in the decimal part
            if x >= self.hex_offset_x:
                rel_x = x - self.hex_offset_x
                col = rel_x // (4 * self.char_width)

                # Ensure col is within the row
                col = min(col, self.bytes_per_row - 1)

                # Calculate final offset
                offset = row_offset + col

                # Ensure the offset is within the file
                if offset < file_size:
                    return offset
        elif self.view_mode == ViewMode.BINARY:
            # Check if click is in the binary part
            if x >= self.hex_offset_x:
                rel_x = x - self.hex_offset_x
                col = rel_x // (9 * self.char_width)

                # Ensure col is within the row
                col = min(col, self.bytes_per_row - 1)

                # Calculate final offset
                offset = row_offset + col

                # Ensure the offset is within the file
                if offset < file_size:
                    return offset

        return -1

    def get_performance_widget(self):
        """
        Get the performance monitoring widget.

        Returns:
            Performance monitoring widget or None if not available
        """
        return self.performance_monitor.create_widget(self)

    def get_performance_stats(self):
        """
        Get current performance statistics.

        Returns:
            Dictionary with performance statistics
        """
        return self.performance_monitor.get_stats_summary()

    def show_performance_dialog(self):
        """Show a dialog with performance statistics."""
        try:
            from PyQt5.QtWidgets import QDialog, QLabel, QPushButton, QTextEdit, QVBoxLayout

            dialog = QDialog(self)
            dialog.setWindowTitle("Hex Viewer Performance Statistics")
            dialog.resize(500, 400)

            layout = QVBoxLayout(dialog)

            # Get stats
            stats = self.get_performance_stats()

            if stats:
                # Create performance widget
                perf_widget = self.get_performance_widget()
                if perf_widget:
                    layout.addWidget(perf_widget)
                else:
                    # Fallback to text display
                    stats_text = QTextEdit()
                    stats_text.setReadOnly(True)

                    text_content = "Performance Statistics:\n\n"
                    for key, value in stats.items():
                        text_content += f"{key}: {value}\n"

                    stats_text.setPlainText(text_content)
                    layout.addWidget(stats_text)
            else:
                label = QLabel("No performance statistics available")
                layout.addWidget(label)

            # Close button
            close_button = QPushButton("Close")
            close_button.clicked.connect(dialog.close)
            layout.addWidget(close_button)

            dialog.exec_()

        except Exception as e:
            logger.error("Error showing performance dialog: %s", e)

    def optimize_for_large_files(self):
        """Optimize settings for large file handling."""
        if self.file_handler and hasattr(self.file_handler, 'large_file_handler'):
            # Auto-optimize based on access patterns
            if hasattr(self.file_handler, 'optimize_for_sequential_access'):
                self.file_handler.optimize_for_sequential_access()

            logger.info("Optimized hex viewer for large file handling")
