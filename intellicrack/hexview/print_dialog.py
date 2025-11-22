"""Print Dialog for Hex Viewer.

This dialog provides configuration options for printing hex data.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from typing import Optional

from PyQt6.QtCore import QRectF
from PyQt6.QtGui import QFont, QFontMetrics, QPainter
from PyQt6.QtPrintSupport import QPrintDialog, QPrinter, QPrintPreviewDialog
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFontComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..utils.logger import get_logger


logger = get_logger(__name__)


class PrintOptionsDialog(QDialog):
    """Dialog for configuring print options."""

    def __init__(
        self,
        parent: QWidget | None = None,
        hex_viewer: QWidget | None = None,
    ) -> None:
        """Initialize print options dialog.

        Args:
            parent: Parent widget for the dialog.
            hex_viewer: Reference to hex viewer widget instance.

        """
        super().__init__(parent)
        self.hex_viewer = hex_viewer
        self.printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        self.setWindowTitle("Print Options")
        self.resize(500, 600)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize UI components."""
        layout = QVBoxLayout()

        # Range selection
        range_group = QGroupBox("Print Range")
        range_layout = QVBoxLayout()

        self.all_pages_check = QCheckBox("All pages")
        self.all_pages_check.setChecked(True)
        self.all_pages_check.toggled.connect(self.on_range_changed)
        range_layout.addWidget(self.all_pages_check)

        self.selection_check = QCheckBox("Selection only")
        self.selection_check.setEnabled(False)
        self.selection_check.toggled.connect(self.on_range_changed)

        # Check if there's a selection
        if self.hex_viewer and hasattr(self.hex_viewer, "selection_start") and (self.hex_viewer.selection_start != -1 and self.hex_viewer.selection_end != -1):
            self.selection_check.setEnabled(True)
            selection_size = self.hex_viewer.selection_end - self.hex_viewer.selection_start
            self.selection_check.setText(f"Selection only ({selection_size} bytes)")

        range_layout.addWidget(self.selection_check)

        page_range_layout = QHBoxLayout()
        self.page_range_check = QCheckBox("Page range:")
        self.page_range_check.toggled.connect(self.on_range_changed)
        page_range_layout.addWidget(self.page_range_check)

        page_range_layout.addWidget(QLabel("From:"))
        self.from_page_spin = QSpinBox()
        self.from_page_spin.setMinimum(1)
        self.from_page_spin.setValue(1)
        self.from_page_spin.setEnabled(False)
        page_range_layout.addWidget(self.from_page_spin)

        page_range_layout.addWidget(QLabel("To:"))
        self.to_page_spin = QSpinBox()
        self.to_page_spin.setMinimum(1)
        self.to_page_spin.setValue(1)
        self.to_page_spin.setEnabled(False)
        page_range_layout.addWidget(self.to_page_spin)

        page_range_layout.addStretch()
        range_layout.addLayout(page_range_layout)

        range_group.setLayout(range_layout)
        layout.addWidget(range_group)

        # Font settings
        font_group = QGroupBox("Font Settings")
        font_layout = QVBoxLayout()

        font_select_layout = QHBoxLayout()
        font_select_layout.addWidget(QLabel("Font:"))
        self.font_combo = QFontComboBox()
        self.font_combo.setCurrentFont(QFont("Courier New"))
        font_select_layout.addWidget(self.font_combo)

        font_select_layout.addWidget(QLabel("Size:"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setMinimum(6)
        self.font_size_spin.setMaximum(20)
        self.font_size_spin.setValue(10)
        font_select_layout.addWidget(self.font_size_spin)

        font_layout.addLayout(font_select_layout)
        font_group.setLayout(font_layout)
        layout.addWidget(font_group)

        # Layout settings
        layout_group = QGroupBox("Layout")
        layout_layout = QVBoxLayout()

        bytes_layout = QHBoxLayout()
        bytes_layout.addWidget(QLabel("Bytes per row:"))
        self.bytes_per_row_spin = QSpinBox()
        self.bytes_per_row_spin.setMinimum(8)
        self.bytes_per_row_spin.setMaximum(32)
        self.bytes_per_row_spin.setSingleStep(8)
        self.bytes_per_row_spin.setValue(16)
        bytes_layout.addWidget(self.bytes_per_row_spin)
        bytes_layout.addStretch()
        layout_layout.addLayout(bytes_layout)

        self.show_offset_check = QCheckBox("Show offset column")
        self.show_offset_check.setChecked(True)
        layout_layout.addWidget(self.show_offset_check)

        self.show_ascii_check = QCheckBox("Show ASCII column")
        self.show_ascii_check.setChecked(True)
        layout_layout.addWidget(self.show_ascii_check)

        self.show_grid_check = QCheckBox("Show grid lines")
        self.show_grid_check.setChecked(False)
        layout_layout.addWidget(self.show_grid_check)

        layout_group.setLayout(layout_layout)
        layout.addWidget(layout_group)

        # Header/Footer settings
        header_group = QGroupBox("Headers and Footers")
        header_layout = QVBoxLayout()

        self.show_header_check = QCheckBox("Show header")
        self.show_header_check.setChecked(True)
        self.show_header_check.toggled.connect(self.on_header_toggled)
        header_layout.addWidget(self.show_header_check)

        header_text_layout = QHBoxLayout()
        header_text_layout.addWidget(QLabel("Header text:"))
        self.header_edit = QLineEdit("Hex Dump - %filename%")
        header_text_layout.addWidget(self.header_edit)
        header_layout.addLayout(header_text_layout)

        self.show_footer_check = QCheckBox("Show footer")
        self.show_footer_check.setChecked(True)
        self.show_footer_check.toggled.connect(self.on_footer_toggled)
        header_layout.addWidget(self.show_footer_check)

        footer_text_layout = QHBoxLayout()
        footer_text_layout.addWidget(QLabel("Footer text:"))
        self.footer_edit = QLineEdit("Page %page% of %total%")
        footer_text_layout.addWidget(self.footer_edit)
        header_layout.addLayout(footer_text_layout)

        header_layout.addWidget(QLabel("Variables: %filename%, %page%, %total%, %date%"))

        header_group.setLayout(header_layout)
        layout.addWidget(header_group)

        # Color settings
        color_group = QGroupBox("Colors")
        color_layout = QVBoxLayout()

        self.use_colors_check = QCheckBox("Print in color")
        self.use_colors_check.setChecked(False)
        color_layout.addWidget(self.use_colors_check)

        self.highlight_selection_check = QCheckBox("Highlight selection")
        self.highlight_selection_check.setChecked(True)
        self.highlight_selection_check.setEnabled(False)
        color_layout.addWidget(self.highlight_selection_check)

        color_group.setLayout(color_layout)
        layout.addWidget(color_group)

        # Dialog buttons
        button_layout = QHBoxLayout()

        preview_btn = QPushButton("Preview...")
        preview_btn.clicked.connect(self.show_preview)
        button_layout.addWidget(preview_btn)

        button_layout.addStretch()

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.print_document)
        button_box.rejected.connect(self.reject)
        button_layout.addWidget(button_box)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def on_range_changed(self) -> None:
        """Handle print range selection changes."""
        sender = self.sender()

        if sender == self.all_pages_check and self.all_pages_check.isChecked():
            self.selection_check.setChecked(False)
            self.page_range_check.setChecked(False)

        elif sender == self.selection_check and self.selection_check.isChecked():
            self.all_pages_check.setChecked(False)
            self.page_range_check.setChecked(False)

        elif sender == self.page_range_check:
            if self.page_range_check.isChecked():
                self.all_pages_check.setChecked(False)
                self.selection_check.setChecked(False)
                self.from_page_spin.setEnabled(True)
                self.to_page_spin.setEnabled(True)
            else:
                self.from_page_spin.setEnabled(False)
                self.to_page_spin.setEnabled(False)

    def on_header_toggled(self, checked: bool) -> None:
        """Handle header checkbox toggle.

        Args:
            checked: Whether the header checkbox is checked.

        """
        self.header_edit.setEnabled(checked)

    def on_footer_toggled(self, checked: bool) -> None:
        """Handle footer checkbox toggle.

        Args:
            checked: Whether the footer checkbox is checked.

        """
        self.footer_edit.setEnabled(checked)

    def get_print_data(self) -> tuple[bytes | None, int]:
        """Get the data to print based on selected range.

        Returns:
            Tuple of (data, start_offset) where data is the bytes to print
            or None if no data is available, and start_offset is the file
            offset in bytes where the print data begins.

        """
        if not self.hex_viewer or not hasattr(self.hex_viewer, "file_handler"):
            return (None, 0)

        if self.selection_check.isChecked() and self.selection_check.isEnabled():
            # Print selection
            start = self.hex_viewer.selection_start
            end = self.hex_viewer.selection_end
            if start != -1 and end != -1:
                data = self.hex_viewer.file_handler.read_data(start, end - start)
                return (data, start)
        else:
            # Print all or page range
            file_size = self.hex_viewer.file_handler.file_size
            data = self.hex_viewer.file_handler.read_data(0, file_size)
            return (data, 0)

        return (None, 0)

    def format_hex_line(
        self,
        offset: int,
        data_chunk: bytes,
        bytes_per_row: int,
    ) -> str:
        """Format a single line of hex output.

        Args:
            offset: Starting file offset of this line in bytes.
            data_chunk: Bytes for this line to format.
            bytes_per_row: Number of bytes per row to display.

        Returns:
            Formatted hex line string with offset, hex bytes, and optional
            ASCII representation based on current display settings.

        """
        line = ""

        # Add offset if enabled
        if self.show_offset_check.isChecked():
            line += f"{offset:08X}  "

        # Add hex bytes
        hex_str = ""
        for i, byte in enumerate(data_chunk):
            hex_str += f"{byte:02X}"
            if i < len(data_chunk) - 1:
                hex_str += " "
                if (i + 1) % 8 == 0:
                    hex_str += " "

        # Pad hex string if needed
        if len(data_chunk) < bytes_per_row:
            missing = bytes_per_row - len(data_chunk)
            hex_str += "   " * missing
            if len(data_chunk) <= 8:
                hex_str += " "

        line += hex_str

        # Add ASCII if enabled
        if self.show_ascii_check.isChecked():
            line += "  "
            ascii_str = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in data_chunk
            )
            # Pad ASCII if needed
            if len(data_chunk) < bytes_per_row:
                ascii_str += " " * (bytes_per_row - len(data_chunk))
            line += ascii_str

        return line

    def render_page(
        self,
        painter: QPainter,
        page_rect: QRectF,
        data: bytes,
        start_offset: int,
        page_num: int,
        total_pages: int,
    ) -> None:
        """Render a page of hex data.

        Args:
            painter: QPainter instance to draw with.
            page_rect: Rectangle defining the page content area.
            data: Bytes data to print.
            start_offset: Starting file offset in bytes where data begins.
            page_num: Current page number being rendered (1-indexed).
            total_pages: Total number of pages being printed.

        """
        # Set up font
        font = self.font_combo.currentFont()
        font.setPointSize(self.font_size_spin.value())
        font.setFamily(font.family())  # Ensure monospace
        painter.setFont(font)

        metrics = QFontMetrics(font)
        line_height = metrics.height()

        # Calculate printable area
        margin = 20
        content_rect = page_rect.adjusted(margin, margin, -margin, -margin)

        # Draw header if enabled
        y_pos = content_rect.top()
        if self.show_header_check.isChecked():
            header_text = self.header_edit.text()
            header_text = self.replace_variables(header_text, page_num, total_pages)
            painter.drawText(content_rect.left(), y_pos, header_text)
            y_pos += line_height * 2

        # Calculate lines per page
        available_height = content_rect.height()
        if self.show_footer_check.isChecked():
            available_height -= line_height * 2
        lines_per_page = int(available_height / line_height) - 2

        # Render hex lines
        bytes_per_row = self.bytes_per_row_spin.value()
        bytes_per_page = lines_per_page * bytes_per_row

        # Calculate page data range
        page_start = (page_num - 1) * bytes_per_page
        page_end = min(page_start + bytes_per_page, len(data))

        if page_start < len(data):
            for line_num in range(lines_per_page):
                data_start = page_start + (line_num * bytes_per_row)
                if data_start >= page_end:
                    break

                data_end = min(data_start + bytes_per_row, page_end)
                if data_chunk := data[data_start:data_end]:
                    line = self.format_hex_line(
                        start_offset + data_start, data_chunk, bytes_per_row
                    )
                    painter.drawText(content_rect.left(), y_pos, line)
                    y_pos += line_height

        # Draw footer if enabled
        if self.show_footer_check.isChecked():
            footer_text = self.footer_edit.text()
            footer_text = self.replace_variables(footer_text, page_num, total_pages)
            footer_y = content_rect.bottom() - line_height
            painter.drawText(content_rect.left(), footer_y, footer_text)

    def replace_variables(
        self,
        text: str,
        page_num: int,
        total_pages: int,
    ) -> str:
        """Replace variables in header/footer text.

        Args:
            text: Text containing variables to replace.
            page_num: Current page number (1-indexed).
            total_pages: Total number of pages.

        Returns:
            Text with variables replaced. Supported variables are:
            %filename% (source file name), %page% (current page number),
            %total% (total pages), and %date% (current date and time).

        """
        import datetime

        # Get filename
        filename = "Untitled"
        if self.hex_viewer and hasattr(self.hex_viewer.file_handler, "file_path"):
            import os

            filename = os.path.basename(self.hex_viewer.file_handler.file_path)

        text = text.replace("%filename%", filename)
        text = text.replace("%page%", str(page_num))
        text = text.replace("%total%", str(total_pages))
        return text.replace(
            "%date%", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )

    def calculate_total_pages(self, data: bytes) -> int:
        """Calculate total number of pages.

        Args:
            data: Data bytes to be printed.

        Returns:
            Total number of pages required to print all data given current
            page size, font settings, and header/footer configuration.

        """
        if not data:
            return 0

        # Set up font metrics
        font = self.font_combo.currentFont()
        font.setPointSize(self.font_size_spin.value())
        metrics = QFontMetrics(font)
        line_height = metrics.height()

        # Get page size
        page_rect = self.printer.pageRect(QPrinter.Unit.DevicePixel)
        margin = 20
        content_rect = page_rect.adjusted(margin, margin, -margin, -margin)

        # Calculate lines per page
        available_height = content_rect.height()
        if self.show_header_check.isChecked():
            available_height -= line_height * 2
        if self.show_footer_check.isChecked():
            available_height -= line_height * 2
        lines_per_page = int(available_height / line_height) - 2

        # Calculate total pages
        bytes_per_row = self.bytes_per_row_spin.value()
        bytes_per_page = lines_per_page * bytes_per_row
        total_pages = (len(data) + bytes_per_page - 1) // bytes_per_page

        return max(1, total_pages)

    def show_preview(self) -> None:
        """Show print preview dialog."""
        preview = QPrintPreviewDialog(self.printer, self)
        preview.paintRequested.connect(self.on_print_preview)
        preview.exec()

    def on_print_preview(self, printer: QPrinter) -> None:
        """Handle print preview paint request.

        Args:
            printer: QPrinter instance to render preview to.

        """
        self.render_to_printer(printer)

    def print_document(self) -> None:
        """Print the document."""
        # Show native print dialog
        print_dialog = QPrintDialog(self.printer, self)
        if print_dialog.exec() == QDialog.DialogCode.Accepted:
            self.render_to_printer(self.printer)
            self.accept()

    def render_to_printer(self, printer: QPrinter) -> None:
        """Render the hex data to a printer.

        Args:
            printer: QPrinter instance to render hex data to.

        """
        # Get data to print
        data, start_offset = self.get_print_data()
        if data is None:
            QMessageBox.warning(self, "No Data", "No data to print.")
            return

        # Calculate total pages
        total_pages = self.calculate_total_pages(data)

        # Set up painter
        painter = QPainter()
        if not painter.begin(printer):
            QMessageBox.critical(self, "Print Error", "Failed to start printing.")
            return

        try:
            # Determine page range
            if self.page_range_check.isChecked():
                from_page = self.from_page_spin.value()
                to_page = min(self.to_page_spin.value(), total_pages)
            else:
                from_page = 1
                to_page = total_pages

            # Render pages
            for page_num in range(from_page, to_page + 1):
                if page_num > from_page:
                    printer.newPage()

                page_rect = printer.pageRect(QPrinter.Unit.DevicePixel)
                self.render_page(painter, page_rect, data, start_offset, page_num, total_pages)

        finally:
            painter.end()

        logger.info(f"Printed {to_page - from_page + 1} pages")
