"""Hex viewer widget for binary file analysis.

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

import math

from intellicrack.handlers.pyqt6_handler import (
    QColor,
    QFont,
    QHBoxLayout,
    QKeyEvent,
    QLabel,
    QLineEdit,
    QPainter,
    QPushButton,
    QScrollBar,
    Qt,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


class HexViewerWidget(QWidget):
    """Professional hex viewer widget with editing capabilities."""

    #: start, end offsets (type: int, int)
    selection_changed = pyqtSignal(int, int)
    #: offset, new_data (type: int, bytes)
    data_modified = pyqtSignal(int, bytes)

    def __init__(self, parent=None) -> None:
        """Initialize hex viewer widget with binary data visualization and editing capabilities."""
        super().__init__(parent)
        self.data = b""
        self.selected_start = -1
        self.selected_end = -1
        self.bytes_per_row = 16
        self.current_offset = 0

        self.setup_ui()
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def setup_ui(self) -> None:
        """Set up the hex viewer UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Control bar
        control_layout = QHBoxLayout()

        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search hex (e.g., 4D 5A 90)")
        self.search_box.returnPressed.connect(self.search_hex)
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)

        # Go to offset
        self.offset_box = QLineEdit()
        self.offset_box.setPlaceholderText("Offset (hex)")
        self.offset_box.setMaximumWidth(100)
        self.offset_box.returnPressed.connect(self.goto_offset)
        control_layout.addWidget(QLabel("Go to:"))
        control_layout.addWidget(self.offset_box)

        # Edit mode toggle
        self.edit_toggle = QPushButton("Edit Mode")
        self.edit_toggle.setCheckable(True)
        self.edit_toggle.toggled.connect(self.toggle_edit_mode)
        control_layout.addWidget(self.edit_toggle)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        # Main hex display area
        display_layout = QHBoxLayout()

        # Hex display widget
        self.hex_display = HexDisplay(self)
        self.hex_display.cursor_moved.connect(self.update_cursor_info)

        # Vertical scrollbar
        self.v_scrollbar = QScrollBar(Qt.Orientation.Vertical)
        self.v_scrollbar.valueChanged.connect(self.scroll_to)

        display_layout.addWidget(self.hex_display)
        display_layout.addWidget(self.v_scrollbar)

        layout.addLayout(display_layout)

        # Status bar
        self.status_label = QLabel("Offset: 0x00000000 | Selection: None")
        layout.addWidget(self.status_label)

    def load_data(self, data: bytes) -> None:
        """Load binary data into the viewer."""
        self.data = bytearray(data)
        self.offset = 0
        self.update_scrollbar()
        self.hex_display.update()

    def update_scrollbar(self) -> None:
        """Update scrollbar range based on data size."""
        if not self.data:
            self.v_scrollbar.setRange(0, 0)
            return

        total_lines = math.ceil(len(self.data) / self.bytes_per_line)
        visible_lines = self.hex_display.visible_lines()

        self.v_scrollbar.setRange(0, max(0, total_lines - visible_lines))
        self.v_scrollbar.setPageStep(visible_lines)

    def scroll_to(self, value) -> None:
        """Scroll to specified line."""
        self.offset = value * self.bytes_per_line
        self.hex_display.update()

    def search_hex(self) -> None:
        """Search for hex pattern in data."""
        pattern = self.search_box.text().strip()
        if not pattern:
            return

        # Convert hex string to bytes
        try:
            search_bytes = bytes.fromhex(pattern.replace(" ", ""))
        except ValueError:
            self.status_label.setText("Invalid hex pattern")
            return

        # Search from current position
        start = self.cursor_pos + 1
        pos = self.data.find(search_bytes, start)

        if pos == -1 and start > 0:
            # Wrap around
            pos = self.data.find(search_bytes, 0, start)

        if pos != -1:
            self.cursor_pos = pos
            self.selection_start = pos
            self.selection_end = pos + len(search_bytes)
            self.scroll_to_offset(pos)
            self.hex_display.update()
            self.status_label.setText(f"Found at offset: 0x{pos:08X}")
        else:
            self.status_label.setText("Pattern not found")

    def goto_offset(self) -> None:
        """Jump to specified offset."""
        try:
            offset = int(self.offset_box.text(), 16)
            if 0 <= offset < len(self.data):
                self.cursor_pos = offset
                self.scroll_to_offset(offset)
                self.hex_display.update()
            else:
                self.status_label.setText("Offset out of range")
        except ValueError:
            self.status_label.setText("Invalid offset")

    def scroll_to_offset(self, offset) -> None:
        """Scroll to make offset visible."""
        line = offset // self.bytes_per_line
        self.v_scrollbar.setValue(line - self.hex_display.visible_lines() // 2)

    def toggle_edit_mode(self, checked) -> None:
        """Toggle edit mode."""
        self.edit_mode = checked
        self.hex_display.update()
        self.status_label.setText(f"Edit mode: {'ON' if checked else 'OFF'}")

    def update_cursor_info(self, offset) -> None:
        """Update status bar with cursor information."""
        if offset < 0 or offset >= len(self.data):
            return

        byte_val = self.data[offset]
        ascii_val = chr(byte_val) if 32 <= byte_val <= 126 else "."

        selection_info = "None"
        if self.selection_start != -1 and self.selection_end != -1:
            selection_info = (
                f"0x{self.selection_start:08X} - 0x{self.selection_end - 1:08X} ({self.selection_end - self.selection_start} bytes)"
            )

        self.status_label.setText(
            f"Offset: 0x{offset:08X} | Byte: 0x{byte_val:02X} ({byte_val}) '{ascii_val}' | Selection: {selection_info}",
        )


class HexDisplay(QWidget):
    """Customize widget for rendering hex data."""

    cursor_moved = pyqtSignal(int)

    def __init__(self, parent=None) -> None:
        """Initialize hex display widget with scrollable hex and ASCII data view."""
        super().__init__(parent)
        self.data = b""
        self.bytes_per_row = 16
        self.selected_start = -1
        self.selected_end = -1
        self.current_offset = 0

        # Use monospace font for proper alignment
        font = QFont("Courier", 10)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.setFont(font)

        # Set minimum size
        self.setMinimumSize(600, 400)

        # Enable mouse tracking for hover effects
        self.setMouseTracking(True)

        # Set background color
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

    def visible_lines(self):
        """Calculate number of visible lines."""
        return self.height() // self.char_height

    def paintEvent(self, event) -> None:
        """Paint the hex display."""
        if not self.hex_viewer.data:
            return

        painter = QPainter(self)
        painter.setFont(self.font)

        # Background
        painter.fillRect(event.rect(), QColor(240, 240, 240))

        # Calculate visible range
        start_line = self.hex_viewer.offset // self.hex_viewer.bytes_per_line
        visible_lines = self.visible_lines()

        # Draw each line
        for line in range(visible_lines):
            y = line * self.char_height + self.char_height
            offset = (start_line + line) * self.hex_viewer.bytes_per_line

            if offset >= len(self.hex_viewer.data):
                break

            # Draw offset
            painter.setPen(QColor(100, 100, 100))
            painter.drawText(0, y, f"{offset:08X}: ")

            # Draw hex bytes
            x = self.offset_width
            for i in range(self.hex_viewer.bytes_per_line):
                byte_offset = offset + i
                if byte_offset >= len(self.hex_viewer.data):
                    break

                byte_val = self.hex_viewer.data[byte_offset]

                # Highlight selection
                if self.hex_viewer.selection_start <= byte_offset < self.hex_viewer.selection_end:
                    painter.fillRect(
                        x,
                        y - self.char_height + 3,
                        2 * self.char_width,
                        self.char_height,
                        QColor(100, 150, 255),
                    )

                # Highlight cursor
                if byte_offset == self.hex_viewer.cursor_pos:
                    painter.fillRect(
                        x,
                        y - self.char_height + 3,
                        2 * self.char_width,
                        self.char_height,
                        QColor(255, 200, 100),
                    )

                painter.setPen(Qt.GlobalColor.black)
                painter.drawText(x, y, f"{byte_val:02X}")
                x += 3 * self.char_width

            # Draw ASCII
            x = self.offset_width + self.hex_width + 20
            for i in range(self.hex_viewer.bytes_per_line):
                byte_offset = offset + i
                if byte_offset >= len(self.hex_viewer.data):
                    break

                byte_val = self.hex_viewer.data[byte_offset]
                ascii_char = chr(byte_val) if 32 <= byte_val <= 126 else "."

                # Highlight selection
                if self.hex_viewer.selection_start <= byte_offset < self.hex_viewer.selection_end:
                    painter.fillRect(
                        x,
                        y - self.char_height + 3,
                        self.char_width,
                        self.char_height,
                        QColor(100, 150, 255),
                    )

                painter.setPen(Qt.GlobalColor.black)
                painter.drawText(x, y, ascii_char)
                x += self.char_width

    def mousePressEvent(self, event) -> None:
        """Handle mouse clicks."""
        pos = self.get_offset_from_pos(event.pos())
        if pos != -1:
            self.hex_viewer.cursor_pos = pos
            self.hex_viewer.selection_start = pos
            self.hex_viewer.selection_end = pos
            self.update()
            self.cursor_moved.emit(pos)

    def mouseMoveEvent(self, event) -> None:
        """Handle mouse drag for selection."""
        if event.buttons() & Qt.MouseButton.LeftButton:
            pos = self.get_offset_from_pos(event.pos())
            if pos != -1:
                self.hex_viewer.selection_end = pos + 1
                self.update()

    def mouseReleaseEvent(self, event) -> None:
        """Handle mouse release."""
        if self.hex_viewer.selection_start != -1 and self.hex_viewer.selection_end != -1:
            # Normalize selection
            start = min(self.hex_viewer.selection_start, self.hex_viewer.selection_end)
            end = max(self.hex_viewer.selection_start, self.hex_viewer.selection_end)
            self.hex_viewer.selection_start = start
            self.hex_viewer.selection_end = end
            self.hex_viewer.selection_changed.emit(start, end)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Handle keyboard input."""
        if not self.hex_viewer.data:
            return

        key = event.key()
        modifiers = event.modifiers()

        # Navigation
        if key == Qt.Key.Key_Left:
            self.hex_viewer.cursor_pos = max(0, self.hex_viewer.cursor_pos - 1)
        elif key == Qt.Key.Key_Right:
            self.hex_viewer.cursor_pos = min(len(self.hex_viewer.data) - 1, self.hex_viewer.cursor_pos + 1)
        elif key == Qt.Key.Key_Up:
            self.hex_viewer.cursor_pos = max(0, self.hex_viewer.cursor_pos - self.hex_viewer.bytes_per_line)
        elif key == Qt.Key.Key_Down:
            self.hex_viewer.cursor_pos = min(
                len(self.hex_viewer.data) - 1,
                self.hex_viewer.cursor_pos + self.hex_viewer.bytes_per_line,
            )
        elif key == Qt.Key.Key_Home:
            if modifiers & Qt.KeyboardModifier.ControlModifier:
                self.hex_viewer.cursor_pos = 0
            else:
                line_start = (self.hex_viewer.cursor_pos // self.hex_viewer.bytes_per_line) * self.hex_viewer.bytes_per_line
                self.hex_viewer.cursor_pos = line_start
        elif key == Qt.Key.Key_End:
            if modifiers & Qt.KeyboardModifier.ControlModifier:
                self.hex_viewer.cursor_pos = len(self.hex_viewer.data) - 1
            else:
                line_start = (self.hex_viewer.cursor_pos // self.hex_viewer.bytes_per_line) * self.hex_viewer.bytes_per_line
                line_end = min(line_start + self.hex_viewer.bytes_per_line - 1, len(self.hex_viewer.data) - 1)
                self.hex_viewer.cursor_pos = line_end

        # Editing (if enabled)
        elif self.hex_viewer.edit_mode and event.text():
            char = event.text().upper()
            if char in "0123456789ABCDEF":
                # Hex input mode
                self.input_hex_nibble(char)

        self.hex_viewer.scroll_to_offset(self.hex_viewer.cursor_pos)
        self.update()
        self.cursor_moved.emit(self.hex_viewer.cursor_pos)

    def get_offset_from_pos(self, pos):
        """Calculate byte offset from mouse position."""
        x = pos.x()
        y = pos.y()

        line = y // self.char_height
        start_line = self.hex_viewer.offset // self.hex_viewer.bytes_per_line

        # Check if in hex area
        if self.offset_width <= x < self.offset_width + self.hex_width:
            byte_x = (x - self.offset_width) // (3 * self.char_width)
            byte_offset = (start_line + line) * self.hex_viewer.bytes_per_line + byte_x

            if 0 <= byte_offset < len(self.hex_viewer.data):
                return byte_offset

        # Check if in ASCII area
        elif self.offset_width + self.hex_width + 20 <= x:
            byte_x = (x - self.offset_width - self.hex_width - 20) // self.char_width
            byte_offset = (start_line + line) * self.hex_viewer.bytes_per_line + byte_x

            if 0 <= byte_offset < len(self.hex_viewer.data):
                return byte_offset

        return -1

    def input_hex_nibble(self, char) -> None:
        """Input a hex nibble at current position."""
        if self.hex_viewer.cursor_pos >= len(self.hex_viewer.data):
            return

        # Get current byte
        current_byte = self.hex_viewer.data[self.hex_viewer.cursor_pos]

        # Update high or low nibble based on cursor sub-position
        # For simplicity, always update high nibble and advance
        new_byte = (int(char, 16) << 4) | (current_byte & 0x0F)

        # Update data
        self.hex_viewer.data[self.hex_viewer.cursor_pos] = new_byte
        self.hex_viewer.data_modified.emit(self.hex_viewer.cursor_pos, bytes([new_byte]))

        # Advance cursor
        self.hex_viewer.cursor_pos = min(len(self.hex_viewer.data) - 1, self.hex_viewer.cursor_pos + 1)
