"""Export Dialog for Hex Viewer.

This dialog provides options for exporting data in various formats.

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

import os

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
)

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ExportDialog(QDialog):
    """Dialog for exporting data in various formats."""

    FORMATS = {
        "Raw Binary": "bin",
        "Hex Text": "txt",
        "C Array": "c",
        "C++ Array": "cpp",
        "Java Array": "java",
        "Python Bytes": "py",
        "Intel Hex": "hex",
        "Motorola S-Record": "srec",
        "Base64": "b64",
        "Data URI": "uri",
    }

    def __init__(self, parent=None, hex_viewer=None) -> None:
        """Initialize export dialog.

        Args:
            parent: Parent widget
            hex_viewer: Reference to hex viewer widget

        """
        super().__init__(parent)
        self.hex_viewer = hex_viewer
        self.setWindowTitle("Export Data")
        self.resize(500, 400)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize UI components."""
        layout = QVBoxLayout()

        # Data source selection
        source_group = QGroupBox("Data Source")
        source_layout = QVBoxLayout()

        self.entire_file_radio = QRadioButton("Entire file")
        self.entire_file_radio.setChecked(True)
        source_layout.addWidget(self.entire_file_radio)

        self.selection_radio = QRadioButton("Current selection")
        self.selection_radio.setEnabled(False)
        source_layout.addWidget(self.selection_radio)

        # Check if there's a selection
        if self.hex_viewer and hasattr(self.hex_viewer, "selection_start"):
            if self.hex_viewer.selection_start != -1 and self.hex_viewer.selection_end != -1:
                self.selection_radio.setEnabled(True)
                selection_size = self.hex_viewer.selection_end - self.hex_viewer.selection_start
                self.selection_radio.setText(f"Current selection ({selection_size} bytes)")

        source_group.setLayout(source_layout)
        layout.addWidget(source_group)

        # Export format selection
        format_group = QGroupBox("Export Format")
        format_layout = QVBoxLayout()

        format_combo_layout = QHBoxLayout()
        format_combo_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(self.FORMATS.keys())
        self.format_combo.currentTextChanged.connect(self.on_format_changed)
        format_combo_layout.addWidget(self.format_combo)
        format_combo_layout.addStretch()
        format_layout.addLayout(format_combo_layout)

        # Format-specific options
        self.options_group = QGroupBox("Format Options")
        self.options_layout = QVBoxLayout()

        # Hex text options
        self.hex_uppercase_check = QCheckBox("Uppercase hex")
        self.hex_uppercase_check.setChecked(True)
        self.options_layout.addWidget(self.hex_uppercase_check)

        # Array options
        array_layout = QHBoxLayout()
        array_layout.addWidget(QLabel("Items per line:"))
        self.items_per_line_spin = QSpinBox()
        self.items_per_line_spin.setMinimum(1)
        self.items_per_line_spin.setMaximum(32)
        self.items_per_line_spin.setValue(16)
        array_layout.addWidget(self.items_per_line_spin)
        array_layout.addStretch()
        self.options_layout.addLayout(array_layout)

        self.include_size_check = QCheckBox("Include size constant")
        self.include_size_check.setChecked(True)
        self.options_layout.addWidget(self.include_size_check)

        # Variable name for arrays
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Variable name:"))
        self.var_name_edit = QLineEdit("data")
        name_layout.addWidget(self.var_name_edit)
        name_layout.addStretch()
        self.options_layout.addLayout(name_layout)

        self.options_group.setLayout(self.options_layout)
        format_layout.addWidget(self.options_group)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # File selection
        file_group = QGroupBox("Output File")
        file_layout = QVBoxLayout()

        file_select_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        file_select_layout.addWidget(self.file_path_edit)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        file_select_layout.addWidget(browse_btn)

        file_layout.addLayout(file_select_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.export_data)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

        # Initialize format options
        self.on_format_changed(self.format_combo.currentText())

    def on_format_changed(self, format_name: str) -> None:
        """Handle format selection change.

        Args:
            format_name: Selected format name

        """
        # Show/hide relevant options based on format
        is_hex_text = format_name == "Hex Text"
        is_array = format_name in ["C Array", "C++ Array", "Java Array", "Python Bytes"]

        self.hex_uppercase_check.setVisible(is_hex_text or is_array)
        self.items_per_line_spin.parent().setVisible(is_array)
        self.include_size_check.setVisible(is_array)
        self.var_name_edit.parent().setVisible(is_array)

        # Update default extension
        if self.file_path_edit.text():
            base_name = os.path.splitext(self.file_path_edit.text())[0]
            ext = self.FORMATS.get(format_name, "bin")
            self.file_path_edit.setText(f"{base_name}.{ext}")

    def browse_file(self) -> None:
        """Show file save dialog."""
        format_name = self.format_combo.currentText()
        ext = self.FORMATS.get(format_name, "bin")

        filters = {
            "Raw Binary": "Binary Files (*.bin);;All Files (*)",
            "Hex Text": "Text Files (*.txt);;All Files (*)",
            "C Array": "C Source Files (*.c);;Header Files (*.h);;All Files (*)",
            "C++ Array": "C++ Source Files (*.cpp);;Header Files (*.h);;All Files (*)",
            "Java Array": "Java Source Files (*.java);;All Files (*)",
            "Python Bytes": "Python Files (*.py);;All Files (*)",
            "Intel Hex": "Intel Hex Files (*.hex);;All Files (*)",
            "Motorola S-Record": "S-Record Files (*.srec *.s19 *.s28 *.s37);;All Files (*)",
            "Base64": "Base64 Files (*.b64 *.txt);;All Files (*)",
            "Data URI": "URI Files (*.uri *.txt);;All Files (*)",
        }

        file_filter = filters.get(format_name, "All Files (*)")

        file_path, _ = QFileDialog.getSaveFileName(self, "Export As", f"export.{ext}", file_filter)

        if file_path:
            self.file_path_edit.setText(file_path)

    def export_data(self) -> None:
        """Export the data in the selected format."""
        if not self.file_path_edit.text():
            QMessageBox.warning(self, "No File", "Please specify an output file.")
            return

        # Get data to export
        data = self.get_export_data()
        if data is None:
            return

        # Get selected format
        format_name = self.format_combo.currentText()

        try:
            # Convert data to selected format
            if format_name == "Raw Binary":
                output = data
            elif format_name == "Hex Text":
                output = self.format_hex_text(data)
            elif format_name == "C Array":
                output = self.format_c_array(data)
            elif format_name == "C++ Array":
                output = self.format_cpp_array(data)
            elif format_name == "Java Array":
                output = self.format_java_array(data)
            elif format_name == "Python Bytes":
                output = self.format_python_bytes(data)
            elif format_name == "Intel Hex":
                output = self.format_intel_hex(data)
            elif format_name == "Motorola S-Record":
                output = self.format_srec(data)
            elif format_name == "Base64":
                output = self.format_base64(data)
            elif format_name == "Data URI":
                output = self.format_data_uri(data)
            else:
                output = data

            # Write to file
            file_path = self.file_path_edit.text()
            mode = "wb" if isinstance(output, bytes) else "w"

            with open(file_path, mode) as f:
                f.write(output)

            QMessageBox.information(self, "Export Complete", f"Data exported successfully to:\n{file_path}")
            self.accept()

        except Exception as e:
            logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export data:\n{e!s}")

    def get_export_data(self) -> bytes | None:
        """Get the data to export based on selection.

        Returns:
            Bytes to export or None if unavailable

        """
        if not self.hex_viewer or not hasattr(self.hex_viewer, "file_handler"):
            QMessageBox.warning(self, "No Data", "No file is loaded.")
            return None

        if self.selection_radio.isChecked() and self.selection_radio.isEnabled():
            # Export selection
            start = self.hex_viewer.selection_start
            end = self.hex_viewer.selection_end
            if start != -1 and end != -1:
                data = self.hex_viewer.file_handler.read_data(start, end - start)
                if data is None:
                    QMessageBox.warning(self, "Read Error", "Failed to read selected data.")
                    return None
                return data
            QMessageBox.warning(self, "No Selection", "No data is selected.")
            return None
        # Export entire file
        file_size = self.hex_viewer.file_handler.file_size
        data = self.hex_viewer.file_handler.read_data(0, file_size)
        if data is None:
            QMessageBox.warning(self, "Read Error", "Failed to read file data.")
            return None
        return data

    def format_hex_text(self, data: bytes) -> str:
        """Format data as hex text.

        Args:
            data: Binary data

        Returns:
            Formatted hex string

        """
        hex_format = "{:02X}" if self.hex_uppercase_check.isChecked() else "{:02x}"
        return " ".join(hex_format.format(b) for b in data)

    def format_c_array(self, data: bytes) -> str:
        """Format data as C array.

        Args:
            data: Binary data

        Returns:
            C array source code

        """
        var_name = self.var_name_edit.text() or "data"
        items_per_line = self.items_per_line_spin.value()
        hex_format = "0x{:02X}" if self.hex_uppercase_check.isChecked() else "0x{:02x}"

        lines = []

        if self.include_size_check.isChecked():
            lines.append(f"#define {var_name.upper()}_SIZE {len(data)}")
            lines.append("")

        lines.append(f"unsigned char {var_name}[] = {{")

        for i in range(0, len(data), items_per_line):
            chunk = data[i : i + items_per_line]
            items = [hex_format.format(b) for b in chunk]
            line = "    " + ", ".join(items)
            if i + items_per_line < len(data):
                line += ","
            lines.append(line)

        lines.append("};")

        return "\n".join(lines)

    def format_cpp_array(self, data: bytes) -> str:
        """Format data as C++ array.

        Args:
            data: Binary data

        Returns:
            C++ array source code

        """
        var_name = self.var_name_edit.text() or "data"
        items_per_line = self.items_per_line_spin.value()
        hex_format = "0x{:02X}" if self.hex_uppercase_check.isChecked() else "0x{:02x}"

        lines = []

        if self.include_size_check.isChecked():
            lines.append(f"constexpr size_t {var_name}_size = {len(data)};")
            lines.append("")

        lines.append(f"const unsigned char {var_name}[] = {{")

        for i in range(0, len(data), items_per_line):
            chunk = data[i : i + items_per_line]
            items = [hex_format.format(b) for b in chunk]
            line = "    " + ", ".join(items)
            if i + items_per_line < len(data):
                line += ","
            lines.append(line)

        lines.append("};")

        return "\n".join(lines)

    def format_java_array(self, data: bytes) -> str:
        """Format data as Java array.

        Args:
            data: Binary data

        Returns:
            Java array source code

        """
        var_name = self.var_name_edit.text() or "data"
        items_per_line = self.items_per_line_spin.value()

        lines = []

        if self.include_size_check.isChecked():
            lines.append(f"public static final int {var_name.upper()}_SIZE = {len(data)};")
            lines.append("")

        lines.append(f"public static final byte[] {var_name} = {{")

        for i in range(0, len(data), items_per_line):
            chunk = data[i : i + items_per_line]
            # Java bytes are signed, so we need to handle values > 127
            items = []
            for b in chunk:
                if b > 127:
                    items.append(f"(byte) 0x{b:02X}")
                else:
                    items.append(f"0x{b:02X}")
            line = "    " + ", ".join(items)
            if i + items_per_line < len(data):
                line += ","
            lines.append(line)

        lines.append("};")

        return "\n".join(lines)

    def format_python_bytes(self, data: bytes) -> str:
        """Format data as Python bytes.

        Args:
            data: Binary data

        Returns:
            Python bytes literal

        """
        var_name = self.var_name_edit.text() or "data"
        items_per_line = self.items_per_line_spin.value()

        lines = []

        if self.include_size_check.isChecked():
            lines.append(f"{var_name.upper()}_SIZE = {len(data)}")
            lines.append("")

        lines.append(f"{var_name} = (")

        for i in range(0, len(data), items_per_line):
            chunk = data[i : i + items_per_line]
            hex_bytes = "".join(f"\\x{b:02x}" for b in chunk)
            lines.append(f'    b"{hex_bytes}"')

        lines.append(")")

        return "\n".join(lines)

    def format_intel_hex(self, data: bytes, base_address: int = 0) -> str:
        """Format data as Intel Hex.

        Args:
            data: Binary data
            base_address: Starting address

        Returns:
            Intel Hex format string

        """
        lines = []
        record_size = 16  # Standard Intel Hex uses 16 bytes per record

        for i in range(0, len(data), record_size):
            chunk = data[i : i + record_size]
            address = base_address + i

            # Build record
            record_type = 0x00  # Data record
            byte_count = len(chunk)

            # Calculate checksum
            checksum = byte_count + (address >> 8) + (address & 0xFF) + record_type
            checksum += sum(chunk)
            checksum = ((~checksum) + 1) & 0xFF

            # Format record
            hex_data = "".join(f"{b:02X}" for b in chunk)
            line = f":{byte_count:02X}{address:04X}{record_type:02X}{hex_data}{checksum:02X}"
            lines.append(line)

        # End-of-file record
        lines.append(":00000001FF")

        return "\n".join(lines)

    def format_srec(self, data: bytes, base_address: int = 0) -> str:
        """Format data as Motorola S-Record.

        Args:
            data: Binary data
            base_address: Starting address

        Returns:
            S-Record format string

        """
        lines = []
        record_size = 16  # Standard S-Record uses 16 bytes per record

        # Header record (S0)
        header = b"HDR"
        header_checksum = len(header) + 3 + sum(header)
        header_checksum = (~header_checksum) & 0xFF
        lines.append(f"S0{len(header) + 3:02X}0000{header.hex().upper()}{header_checksum:02X}")

        # Data records (S1 for 16-bit addressing)
        for i in range(0, len(data), record_size):
            chunk = data[i : i + record_size]
            address = base_address + i

            # Calculate byte count (data + address + checksum)
            byte_count = len(chunk) + 3

            # Calculate checksum
            checksum = byte_count + (address >> 8) + (address & 0xFF)
            checksum += sum(chunk)
            checksum = (~checksum) & 0xFF

            # Format record
            hex_data = "".join(f"{b:02X}" for b in chunk)
            line = f"S1{byte_count:02X}{address:04X}{hex_data}{checksum:02X}"
            lines.append(line)

        # End record (S9 for 16-bit addressing)
        end_checksum = 3 + (base_address >> 8) + (base_address & 0xFF)
        end_checksum = (~end_checksum) & 0xFF
        lines.append(f"S903{base_address:04X}{end_checksum:02X}")

        return "\n".join(lines)

    def format_base64(self, data: bytes) -> str:
        """Format data as Base64.

        Args:
            data: Binary data

        Returns:
            Base64 encoded string

        """
        import base64

        encoded = base64.b64encode(data).decode("ascii")

        # Split into lines of 76 characters (standard MIME line length)
        lines = []
        for i in range(0, len(encoded), 76):
            lines.append(encoded[i : i + 76])

        return "\n".join(lines)

    def format_data_uri(self, data: bytes) -> str:
        """Format data as Data URI.

        Args:
            data: Binary data

        Returns:
            Data URI string

        """
        import base64

        # Try to detect MIME type from data
        mime_type = "application/octet-stream"

        if len(data) >= 4:
            # Check for common file signatures
            if data[:2] == b"\xff\xd8":
                mime_type = "image/jpeg"
            elif data[:8] == b"\x89PNG\r\n\x1a\n":
                mime_type = "image/png"
            elif data[:6] in (b"GIF87a", b"GIF89a"):
                mime_type = "image/gif"
            elif data[:4] == b"%PDF":
                mime_type = "application/pdf"
            elif data[:4] == b"PK\x03\x04":
                mime_type = "application/zip"

        encoded = base64.b64encode(data).decode("ascii")
        return f"data:{mime_type};base64,{encoded}"
