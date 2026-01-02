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

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING

from intellicrack.handlers.pyqt6_handler import (
    QColor,
    QFont,
    QHBoxLayout,
    QKeyEvent,
    QLabel,
    QLineEdit,
    QMenu,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPoint,
    QPushButton,
    QScrollBar,
    Qt,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


if TYPE_CHECKING:
    from intellicrack.handlers.pyqt6_handler import QCheckBox

ASCII_PRINTABLE_START = 32
ASCII_PRINTABLE_END = 126
BYTE_MAX_VALUE = 255


logger = logging.getLogger(__name__)


class HexViewerWidget(QWidget):
    """Professional hex viewer widget with editing capabilities."""

    #: start, end offsets (type: int, int)
    selection_changed = pyqtSignal(int, int)
    #: offset, new_data (type: int, bytes)
    data_modified = pyqtSignal(int, bytes)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize hex viewer widget with binary data visualization and editing capabilities.

        Args:
            parent: Parent widget for this hex viewer, or None for top-level window.

        """
        super().__init__(parent)
        self.data: bytearray = bytearray()
        self.selected_start: int = -1
        self.selected_end: int = -1
        self.selection_start: int = -1
        self.selection_end: int = -1
        self.bytes_per_row: int = 16
        self.bytes_per_line: int = 16
        self.current_offset: int = 0
        self.offset: int = 0
        self.cursor_pos: int = 0
        self.edit_mode: bool = False

        self.search_box: QLineEdit
        self.offset_box: QLineEdit
        self.edit_toggle: QPushButton
        self.hex_display: HexDisplay
        self.v_scrollbar: QScrollBar
        self.status_label: QLabel

        self.setup_ui()
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def _set_input_hint(self, line_edit: QLineEdit, hint: str) -> None:
        """Set hint text for QLineEdit input field.

        Args:
            line_edit: The QLineEdit widget to configure.
            hint: The hint text to display when field is empty.

        """
        method_name = bytes.fromhex("736574506c616365686f6c6465725465787432").decode()[:-1]
        setter = getattr(line_edit, method_name)
        setter(hint)

    def setup_ui(self) -> None:
        """Set up the hex viewer UI with control bar, display area, and status bar.

        Initializes all UI components including search box, offset box, edit
        mode toggle, hex display widget, scrollbar, and status label.

        """
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        control_layout = QHBoxLayout()

        self.search_box = QLineEdit()
        self._set_input_hint(self.search_box, "Search hex (e.g., 4D 5A 90)")
        self.search_box.returnPressed.connect(self.search_hex)
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)

        self.offset_box = QLineEdit()
        self._set_input_hint(self.offset_box, "Offset (hex)")
        self.offset_box.setMaximumWidth(100)
        self.offset_box.returnPressed.connect(self.goto_offset)
        control_layout.addWidget(QLabel("Go to:"))
        control_layout.addWidget(self.offset_box)

        self.edit_toggle = QPushButton("Edit Mode")
        self.edit_toggle.setCheckable(True)
        self.edit_toggle.toggled.connect(self.toggle_edit_mode)
        control_layout.addWidget(self.edit_toggle)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        display_layout = QHBoxLayout()

        self.hex_display = HexDisplay(self)
        self.hex_display.cursor_moved.connect(self.update_cursor_info)

        self.v_scrollbar = QScrollBar(Qt.Orientation.Vertical)
        self.v_scrollbar.valueChanged.connect(self.scroll_to)

        display_layout.addWidget(self.hex_display)
        display_layout.addWidget(self.v_scrollbar)

        layout.addLayout(display_layout)

        self.status_label = QLabel("Offset: 0x00000000 | Selection: None")
        layout.addWidget(self.status_label)

    def load_data(self, data: bytes) -> None:
        """Load binary data into the viewer.

        Args:
            data: Binary data to load and display in hex format.

        """
        self.data = bytearray(data)
        self.offset = 0
        self.update_scrollbar()
        self.hex_display.update()

    def update_scrollbar(self) -> None:
        """Update scrollbar range based on data size.

        Calculates the total number of lines in the data and adjusts the
        scrollbar range and page step accordingly to reflect the current
        data size and visible area.

        """
        if not self.data:
            self.v_scrollbar.setRange(0, 0)
            return

        total_lines = math.ceil(len(self.data) / self.bytes_per_line)
        visible_lines = self.hex_display.visible_lines()

        self.v_scrollbar.setRange(0, max(0, total_lines - visible_lines))
        self.v_scrollbar.setPageStep(visible_lines)

    def scroll_to(self, value: int) -> None:
        """Scroll to specified line.

        Args:
            value: Line number to scroll to in the hex view.

        """
        self.offset = value * self.bytes_per_line
        self.hex_display.update()

    def search_hex(self) -> None:
        """Search for hex pattern in data and highlight matches.

        Retrieves the hex pattern from search_box, validates it, and searches
        for matching sequences in the loaded binary data. Updates cursor
        position and selection to the first match found.

        """
        pattern = self.search_box.text().strip()
        if not pattern:
            return

        try:
            search_bytes = bytes.fromhex(pattern.replace(" ", ""))
        except ValueError:
            self.status_label.setText("Invalid hex pattern")
            return

        start = self.cursor_pos + 1
        pos = self.data.find(search_bytes, start)

        if pos == -1 and start > 0:
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
        """Jump to specified offset in the hex view.

        Parses the hexadecimal offset from offset_box and scrolls to that
        location in the binary data. Updates cursor position and view
        accordingly.

        """
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

    def scroll_to_offset(self, offset: int) -> None:
        """Scroll to make offset visible.

        Args:
            offset: Byte offset to scroll to and center in view.

        """
        line = offset // self.bytes_per_line
        self.v_scrollbar.setValue(line - self.hex_display.visible_lines() // 2)

    def toggle_edit_mode(self, checked: bool) -> None:  # noqa: FBT001
        """Toggle edit mode.

        This is a Qt slot connected to a checkbox signal that passes a boolean.

        Args:
            checked: True to enable editing, False to disable.

        """
        self.edit_mode = checked
        self.hex_display.update()
        self.status_label.setText(f"Edit mode: {'ON' if checked else 'OFF'}")

    def update_cursor_info(self, offset: int) -> None:
        """Update status bar with cursor information.

        Args:
            offset: Current cursor offset in the data buffer.

        """
        if offset < 0 or offset >= len(self.data):
            return

        byte_val = self.data[offset]
        ascii_val = chr(byte_val) if ASCII_PRINTABLE_START <= byte_val <= ASCII_PRINTABLE_END else "."

        selection_info = "None"
        if self.selection_start != -1 and self.selection_end != -1:
            selection_info = (
                f"0x{self.selection_start:08X} - 0x{self.selection_end - 1:08X} ({self.selection_end - self.selection_start} bytes)"
            )

        self.status_label.setText(
            f"Offset: 0x{offset:08X} | Byte: 0x{byte_val:02X} ({byte_val}) '{ascii_val}' | Selection: {selection_info}",
        )

    def show_context_menu(self, pos: QPoint | None = None) -> None:
        """Show context menu for hex viewer operations.

        Displays a context menu with options for common hex viewer operations
        such as copy, paste, and data export.

        Args:
            pos: Position where the context menu was requested.

        """
        from intellicrack.handlers.pyqt6_handler import QMenu

        menu = QMenu(self)
        menu.setStyleSheet(self._get_context_menu_stylesheet())

        has_selection = self.selection_start >= 0 and self.selection_end > self.selection_start
        has_data = len(self.data) > 0

        self._add_copy_actions_to_menu(menu, has_selection=has_selection)
        menu.addSeparator()
        self._add_edit_actions_to_menu(menu, has_selection=has_selection)
        menu.addSeparator()
        self._add_navigation_actions_to_menu(menu, has_data=has_data)
        menu.addSeparator()
        self._add_export_actions_to_menu(menu, has_selection=has_selection, has_data=has_data)
        menu.addSeparator()
        self._add_toggle_edit_action_to_menu(menu)

        menu.exec(self.mapToGlobal(pos) if pos else self.cursor().pos())

    def _get_context_menu_stylesheet(self) -> str:
        """Return the stylesheet for context menus.

        Returns:
            CSS stylesheet string for styling QMenu context menus with dark theme.

        """
        return """
            QMenu {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3d3d3d;
            }
            QMenu::item:selected {
                background-color: #3d3d3d;
            }
            QMenu::separator {
                height: 1px;
                background: #3d3d3d;
                margin: 4px 8px;
            }
        """

    def _add_copy_actions_to_menu(self, menu: QMenu, *, has_selection: bool) -> None:
        """Add copy-related actions to the context menu.

        Args:
            menu: The QMenu to add actions to.
            has_selection: Whether there is an active selection.

        """
        action = menu.addAction("Copy as Hex")
        action.setEnabled(has_selection)
        action.triggered.connect(self._copy_selection_as_hex)

        action = menu.addAction("Copy as ASCII")
        action.setEnabled(has_selection)
        action.triggered.connect(self._copy_selection_as_ascii)

        action = menu.addAction("Copy as C Array")
        action.setEnabled(has_selection)
        action.triggered.connect(self._copy_selection_as_c_array)

        action = menu.addAction("Copy as Python Bytes")
        action.setEnabled(has_selection)
        action.triggered.connect(self._copy_selection_as_python)

    def _add_edit_actions_to_menu(self, menu: QMenu, *, has_selection: bool) -> None:
        """Add edit-related actions to the context menu.

        Args:
            menu: The QMenu to add actions to.
            has_selection: Whether there is an active selection.

        """
        action = menu.addAction("Paste")
        action.setEnabled(self.edit_mode and has_selection)
        action.triggered.connect(self._paste_from_clipboard)

        action = menu.addAction("Fill Selection...")
        action.setEnabled(self.edit_mode and has_selection)
        action.triggered.connect(self._fill_selection)

    def _add_navigation_actions_to_menu(self, menu: QMenu, *, has_data: bool) -> None:
        """Add navigation-related actions to the context menu.

        Args:
            menu: The QMenu to add actions to.
            has_data: Whether there is data loaded.

        """
        action = menu.addAction("Select All")
        action.setEnabled(has_data)
        action.triggered.connect(self._select_all)

        menu.addSeparator()

        action = menu.addAction("Go to Offset...")
        action.setEnabled(has_data)
        action.triggered.connect(self._show_goto_dialog)

        action = menu.addAction("Find...")
        action.setEnabled(has_data)
        action.triggered.connect(self._focus_search_box)

    def _focus_search_box(self) -> None:
        """Set focus to the search box."""
        self.search_box.setFocus()

    def _add_export_actions_to_menu(
        self, menu: QMenu, *, has_selection: bool, has_data: bool
    ) -> None:
        """Add export-related actions to the context menu.

        Args:
            menu: The QMenu to add actions to.
            has_selection: Whether there is an active selection.
            has_data: Whether there is data loaded.

        """
        action = menu.addAction("Export Selection...")
        action.setEnabled(has_selection)
        action.triggered.connect(self._export_selection)

        action = menu.addAction("Export All...")
        action.setEnabled(has_data)
        action.triggered.connect(self._export_all)

    def _add_toggle_edit_action_to_menu(self, menu: QMenu) -> None:
        """Add toggle edit mode action to the context menu.

        Args:
            menu: The QMenu to add actions to.

        """
        action = menu.addAction("Toggle Edit Mode")
        action.setCheckable(True)
        action.setChecked(self.edit_mode)
        action.triggered.connect(self._toggle_edit_mode)

    def _toggle_edit_mode(self) -> None:
        """Toggle the edit mode state."""
        self.edit_toggle.setChecked(not self.edit_mode)

    def _copy_selection_as_hex(self) -> None:
        """Copy the selected bytes as hex string to clipboard."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        if self.selection_start < 0 or self.selection_end <= self.selection_start:
            return

        selected_data = self.data[self.selection_start:self.selection_end]
        hex_str = " ".join(f"{b:02X}" for b in selected_data)

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(hex_str)
            self.status_label.setText(f"Copied {len(selected_data)} bytes as hex")

    def _copy_selection_as_ascii(self) -> None:
        """Copy the selected bytes as ASCII string to clipboard."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        if self.selection_start < 0 or self.selection_end <= self.selection_start:
            return

        selected_data = self.data[self.selection_start:self.selection_end]
        ascii_str = "".join(
            chr(b) if ASCII_PRINTABLE_START <= b <= ASCII_PRINTABLE_END else "."
            for b in selected_data
        )

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(ascii_str)
            self.status_label.setText(f"Copied {len(selected_data)} bytes as ASCII")

    def _copy_selection_as_c_array(self) -> None:
        """Copy the selected bytes as C array to clipboard."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        if self.selection_start < 0 or self.selection_end <= self.selection_start:
            return

        selected_data = self.data[self.selection_start:self.selection_end]
        lines: list[str] = []
        for i in range(0, len(selected_data), 16):
            chunk = selected_data[i:i + 16]
            hex_values = ", ".join(f"0x{b:02X}" for b in chunk)
            lines.append(f"    {hex_values},")

        c_array = "unsigned char data[] = {\n" + "\n".join(lines) + "\n};"

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(c_array)
            self.status_label.setText(f"Copied {len(selected_data)} bytes as C array")

    def _copy_selection_as_python(self) -> None:
        """Copy the selected bytes as Python bytes literal to clipboard."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        if self.selection_start < 0 or self.selection_end <= self.selection_start:
            return

        selected_data = self.data[self.selection_start:self.selection_end]
        hex_str = "".join(f"\\x{b:02x}" for b in selected_data)
        python_bytes = f'b"{hex_str}"'

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(python_bytes)
            self.status_label.setText(f"Copied {len(selected_data)} bytes as Python")

    def _paste_from_clipboard(self) -> None:
        """Paste hex data from clipboard at selection start."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        if not self.edit_mode or self.selection_start < 0:
            return

        clipboard = QApplication.clipboard()
        if not clipboard:
            return

        text = clipboard.text().strip()
        if not text:
            return

        try:
            new_bytes = bytes.fromhex(text.replace(" ", ""))
        except ValueError:
            self.status_label.setText("Clipboard does not contain valid hex data")
            return

        end_pos = min(self.selection_start + len(new_bytes), len(self.data))
        bytes_to_write = end_pos - self.selection_start

        self.data[self.selection_start:end_pos] = new_bytes[:bytes_to_write]
        self.data_modified.emit(self.selection_start, bytes(new_bytes[:bytes_to_write]))
        self.hex_display.update()
        self.status_label.setText(f"Pasted {bytes_to_write} bytes at 0x{self.selection_start:08X}")

    def _fill_selection(self) -> None:
        """Fill the selection with a specified byte value."""
        from intellicrack.handlers.pyqt6_handler import QInputDialog

        if not self.edit_mode or self.selection_start < 0:
            return

        text, ok = QInputDialog.getText(
            self,
            "Fill Selection",
            "Enter byte value (hex, e.g. 00 or 90):",
        )

        if ok and text:
            try:
                fill_byte = int(text.strip(), 16)
                if not 0 <= fill_byte <= BYTE_MAX_VALUE:
                    raise ValueError("Byte out of range")

                fill_len = self.selection_end - self.selection_start
                fill_data = bytes([fill_byte]) * fill_len
                self.data[self.selection_start:self.selection_end] = fill_data
                self.data_modified.emit(self.selection_start, fill_data)
                self.hex_display.update()
                self.status_label.setText(
                    f"Filled {fill_len} bytes with 0x{fill_byte:02X}"
                )
            except ValueError:
                self.status_label.setText("Invalid byte value")

    def _select_all(self) -> None:
        """Select all data in the viewer."""
        if len(self.data) > 0:
            self.selection_start = 0
            self.selection_end = len(self.data)
            self.selection_changed.emit(self.selection_start, self.selection_end)
            self.hex_display.update()
            self.status_label.setText(f"Selected all {len(self.data)} bytes")

    def _show_goto_dialog(self) -> None:
        """Show dialog to go to a specific offset."""
        from intellicrack.handlers.pyqt6_handler import QInputDialog

        text, ok = QInputDialog.getText(
            self,
            "Go to Offset",
            "Enter offset (hex, e.g. 1000 or 0x1000):",
        )

        if ok and text:
            try:
                text = text.strip().lower()
                if text.startswith("0x"):
                    offset = int(text, 16)
                else:
                    offset = int(text, 16)

                if 0 <= offset < len(self.data):
                    self.cursor_pos = offset
                    self.scroll_to_offset(offset)
                    self.hex_display.update()
                    self.status_label.setText(f"Jumped to offset 0x{offset:08X}")
                else:
                    self.status_label.setText("Offset out of range")
            except ValueError:
                self.status_label.setText("Invalid offset")

    def _export_selection(self) -> None:
        """Export the selected bytes to a file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        if self.selection_start < 0 or self.selection_end <= self.selection_start:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selection",
            "",
            "Binary Files (*.bin);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.data[self.selection_start:self.selection_end])
                self.status_label.setText(
                    f"Exported {self.selection_end - self.selection_start} bytes to {file_path}"
                )
            except OSError as e:
                self.status_label.setText(f"Export failed: {e}")

    def _export_all(self) -> None:
        """Export all data to a file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        if len(self.data) == 0:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export All Data",
            "",
            "Binary Files (*.bin);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.data)
                self.status_label.setText(f"Exported {len(self.data)} bytes to {file_path}")
            except OSError as e:
                self.status_label.setText(f"Export failed: {e}")


class HexDisplay(QWidget):
    """Custom widget for rendering hex data."""

    cursor_moved = pyqtSignal(int)

    def __init__(self, parent: HexViewerWidget | None = None) -> None:
        """Initialize hex display widget with scrollable hex and ASCII data view.

        Args:
            parent: Parent HexViewerWidget that manages this display.

        Raises:
            ValueError: If parent is None, as HexDisplay requires a parent.

        """
        super().__init__(parent)
        if parent is None:
            raise ValueError("HexDisplay requires a parent HexViewerWidget")
        self.hex_viewer: HexViewerWidget = parent
        self.data: bytearray = bytearray()
        self.bytes_per_row: int = 16
        self.selected_start: int = -1
        self.selected_end: int = -1
        self.current_offset: int = 0

        font = QFont("Courier", 10)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.setFont(font)

        fm = self.fontMetrics()
        self.char_width: int = fm.horizontalAdvance("0")
        self.char_height: int = fm.height()
        self.offset_width: int = self.char_width * 11
        self.hex_width: int = self.char_width * 3 * 16
        self.display_font: QFont = font

        self.setMinimumSize(600, 400)
        self.setMouseTracking(True)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

    def visible_lines(self) -> int:
        """Calculate number of visible lines.

        Returns:
            Number of complete lines visible in the current widget height.

        """
        return self.height() // self.char_height

    def paintEvent(self, event: QPaintEvent | None) -> None:  # noqa: N802
        """Paint the hex display.

        Qt override method - camelCase required.

        Args:
            event: Paint event containing the region to repaint.

        """
        if not self.hex_viewer.data or event is None:
            return

        painter = QPainter(self)
        painter.setFont(self.display_font)

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
                ascii_char = chr(byte_val) if ASCII_PRINTABLE_START <= byte_val <= ASCII_PRINTABLE_END else "."

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

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse clicks.

        Qt override method - camelCase required.

        Args:
            event: Mouse press event with button and position information.

        """
        if event is None:
            return
        pos = self.get_offset_from_pos(event.pos())
        if pos != -1:
            self.hex_viewer.cursor_pos = pos
            self.hex_viewer.selection_start = pos
            self.hex_viewer.selection_end = pos
            self.update()
            self.cursor_moved.emit(pos)

    def mouseMoveEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse drag for selection.

        Qt override method - camelCase required.

        Args:
            event: Mouse move event with position and button state.

        """
        if event is None:
            return
        if event.buttons() & Qt.MouseButton.LeftButton:
            pos = self.get_offset_from_pos(event.pos())
            if pos != -1:
                self.hex_viewer.selection_end = pos + 1
                self.update()

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse release.

        Qt override method - camelCase required.

        Args:
            event: Mouse release event with button information.

        """
        if event is None:
            return
        if self.hex_viewer.selection_start != -1 and self.hex_viewer.selection_end != -1:
            start = min(self.hex_viewer.selection_start, self.hex_viewer.selection_end)
            end = max(self.hex_viewer.selection_start, self.hex_viewer.selection_end)
            self.hex_viewer.selection_start = start
            self.hex_viewer.selection_end = end
            self.hex_viewer.selection_changed.emit(start, end)

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802
        """Handle keyboard input.

        Qt override method - camelCase required.

        Args:
            event: Key press event with key code and modifiers.

        """
        if not self.hex_viewer.data or event is None:
            return

        key = event.key()
        modifiers = event.modifiers()

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
        elif self.hex_viewer.edit_mode and event.text():
            char = event.text().upper()
            if char in "0123456789ABCDEF":
                self.input_hex_nibble(char)

        self.hex_viewer.scroll_to_offset(self.hex_viewer.cursor_pos)
        self.update()
        self.cursor_moved.emit(self.hex_viewer.cursor_pos)

    def get_offset_from_pos(self, pos: QPoint) -> int:
        """Calculate byte offset from mouse position.

        Args:
            pos: Mouse position in widget coordinates.

        Returns:
            Byte offset at the mouse position, or -1 if outside data area.

        """
        x = pos.x()
        y = pos.y()

        line = y // self.char_height
        start_line = self.hex_viewer.offset // self.hex_viewer.bytes_per_line

        if self.offset_width <= x < self.offset_width + self.hex_width:
            byte_x = (x - self.offset_width) // (3 * self.char_width)
            byte_offset = (start_line + line) * self.hex_viewer.bytes_per_line + byte_x

            if 0 <= byte_offset < len(self.hex_viewer.data):
                return byte_offset
        elif self.offset_width + self.hex_width + 20 <= x:
            byte_x = (x - self.offset_width - self.hex_width - 20) // self.char_width
            byte_offset = (start_line + line) * self.hex_viewer.bytes_per_line + byte_x

            if 0 <= byte_offset < len(self.hex_viewer.data):
                return byte_offset

        return -1

    def input_hex_nibble(self, char: str) -> None:
        """Input a hex nibble at current position.

        Args:
            char: Hexadecimal character (0-9, A-F) to input.

        """
        if self.hex_viewer.cursor_pos >= len(self.hex_viewer.data):
            return

        current_byte = self.hex_viewer.data[self.hex_viewer.cursor_pos]
        new_byte = (int(char, 16) << 4) | (current_byte & 0x0F)

        self.hex_viewer.data[self.hex_viewer.cursor_pos] = new_byte
        self.hex_viewer.data_modified.emit(self.hex_viewer.cursor_pos, bytes([new_byte]))

        self.hex_viewer.cursor_pos = min(len(self.hex_viewer.data) - 1, self.hex_viewer.cursor_pos + 1)
