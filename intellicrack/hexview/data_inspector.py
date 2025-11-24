"""Data Inspector for Hex Viewer.

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

import datetime
import logging
import struct
from enum import Enum

from ..handlers.pyqt6_handler import (
    PYQT6_AVAILABLE,
    QComboBox,
    QFont,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


logger = logging.getLogger(__name__)

__all__ = ["DataInspector", "DataInterpreter", "DataType"]


class DataType(Enum):
    """Enumeration of supported data types."""

    # Integer types
    UINT8 = "uint8"
    INT8 = "int8"
    UINT16_LE = "uint16_le"
    UINT16_BE = "uint16_be"
    INT16_LE = "int16_le"
    INT16_BE = "int16_be"
    UINT32_LE = "uint32_le"
    UINT32_BE = "uint32_be"
    INT32_LE = "int32_le"
    INT32_BE = "int32_be"
    UINT64_LE = "uint64_le"
    UINT64_BE = "uint64_be"
    INT64_LE = "int64_le"
    INT64_BE = "int64_be"

    # Floating point types
    FLOAT32_LE = "float32_le"
    FLOAT32_BE = "float32_be"
    FLOAT64_LE = "float64_le"
    FLOAT64_BE = "float64_be"

    # String types
    ASCII = "ascii"
    UTF8 = "utf8"
    UTF16_LE = "utf16_le"
    UTF16_BE = "utf16_be"
    UTF32_LE = "utf32_le"
    UTF32_BE = "utf32_be"

    # Time types
    UNIX_TIMESTAMP_32 = "unix_timestamp_32"
    UNIX_TIMESTAMP_64 = "unix_timestamp_64"
    WINDOWS_FILETIME = "windows_filetime"
    DOS_DATETIME = "dos_datetime"

    # Special types
    BINARY = "binary"
    HEX = "hex"
    GUID = "guid"
    IPV4_ADDRESS = "ipv4_address"
    IPV6_ADDRESS = "ipv6_address"
    MAC_ADDRESS = "mac_address"


class DataInterpreter:
    """Interprets binary data as various data types."""

    @staticmethod
    def _handle_uint8(data: bytes) -> str:
        """Handle UINT8 data type."""
        return str(data[0]) if data else "Insufficient data"

    @staticmethod
    def _handle_int8(data: bytes) -> str:
        """Handle INT8 data type."""
        return str(struct.unpack("b", data[:1])[0]) if data else "Insufficient data"

    @staticmethod
    def _handle_uint16_le(data: bytes) -> str:
        """Handle UINT16_LE data type."""
        if len(data) >= 2:
            return str(struct.unpack("<H", data[:2])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_uint16_be(data: bytes) -> str:
        """Handle UINT16_BE data type."""
        if len(data) >= 2:
            return str(struct.unpack(">H", data[:2])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int16_le(data: bytes) -> str:
        """Handle INT16_LE data type."""
        if len(data) >= 2:
            return str(struct.unpack("<h", data[:2])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int16_be(data: bytes) -> str:
        """Handle INT16_BE data type."""
        if len(data) >= 2:
            return str(struct.unpack(">h", data[:2])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_uint32_le(data: bytes) -> str:
        """Handle UINT32_LE data type."""
        if len(data) >= 4:
            return str(struct.unpack("<I", data[:4])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_uint32_be(data: bytes) -> str:
        """Handle UINT32_BE data type."""
        if len(data) >= 4:
            return str(struct.unpack(">I", data[:4])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int32_le(data: bytes) -> str:
        """Handle INT32_LE data type."""
        if len(data) >= 4:
            return str(struct.unpack("<i", data[:4])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int32_be(data: bytes) -> str:
        """Handle INT32_BE data type."""
        if len(data) >= 4:
            return str(struct.unpack(">i", data[:4])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_uint64_le(data: bytes) -> str:
        """Handle UINT64_LE data type."""
        if len(data) >= 8:
            return str(struct.unpack("<Q", data[:8])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_uint64_be(data: bytes) -> str:
        """Handle UINT64_BE data type."""
        if len(data) >= 8:
            return str(struct.unpack(">Q", data[:8])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int64_le(data: bytes) -> str:
        """Handle INT64_LE data type."""
        if len(data) >= 8:
            return str(struct.unpack("<q", data[:8])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int64_be(data: bytes) -> str:
        """Handle INT64_BE data type."""
        if len(data) >= 8:
            return str(struct.unpack(">q", data[:8])[0])
        return "Insufficient data"

    @staticmethod
    def _handle_float32_le(data: bytes) -> str:
        """Handle FLOAT32_LE data type."""
        if len(data) >= 4:
            value = struct.unpack("<f", data[:4])[0]
            return f"{value:.6f}"
        return "Insufficient data"

    @staticmethod
    def _handle_float32_be(data: bytes) -> str:
        """Handle FLOAT32_BE data type."""
        if len(data) >= 4:
            value = struct.unpack(">f", data[:4])[0]
            return f"{value:.6f}"
        return "Insufficient data"

    @staticmethod
    def _handle_float64_le(data: bytes) -> str:
        """Handle FLOAT64_LE data type."""
        if len(data) >= 8:
            value = struct.unpack("<d", data[:8])[0]
            return f"{value:.15f}"
        return "Insufficient data"

    @staticmethod
    def _handle_float64_be(data: bytes) -> str:
        """Handle FLOAT64_BE data type."""
        if len(data) >= 8:
            value = struct.unpack(">d", data[:8])[0]
            return f"{value:.15f}"
        return "Insufficient data"

    @staticmethod
    def _handle_ascii(data: bytes) -> str:
        """Handle ASCII data type."""
        try:
            null_pos = data.find(b"\x00")
            text_data = data[:null_pos] if null_pos >= 0 else data
            return text_data.decode("ascii", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid ASCII"

    @staticmethod
    def _handle_utf8(data: bytes) -> str:
        """Handle UTF8 data type."""
        try:
            null_pos = data.find(b"\x00")
            text_data = data[:null_pos] if null_pos >= 0 else data
            return text_data.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid UTF-8"

    @staticmethod
    def _handle_utf16_le(data: bytes) -> str:
        """Handle UTF16_LE data type."""
        try:
            null_pos = data.find(b"\x00\x00")
            text_data = data[:null_pos] if null_pos >= 0 and null_pos % 2 == 0 else data
            return text_data.decode("utf-16le", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid UTF-16 LE"

    @staticmethod
    def _handle_utf16_be(data: bytes) -> str:
        """Handle UTF16_BE data type."""
        try:
            null_pos = data.find(b"\x00\x00")
            text_data = data[:null_pos] if null_pos >= 0 and null_pos % 2 == 0 else data
            return text_data.decode("utf-16be", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid UTF-16 BE"

    @staticmethod
    def _handle_unix_timestamp_32(data: bytes) -> str:
        """Handle UNIX_TIMESTAMP_32 data type."""
        if len(data) >= 4:
            timestamp = struct.unpack("<I", data[:4])[0]
            try:
                dt = datetime.datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError, OverflowError) as e:
                logger.error("Error in data_inspector: %s", e)
                return f"Invalid timestamp: {timestamp}"
        return "Insufficient data"

    @staticmethod
    def _handle_unix_timestamp_64(data: bytes) -> str:
        """Handle UNIX_TIMESTAMP_64 data type."""
        if len(data) >= 8:
            timestamp = struct.unpack("<Q", data[:8])[0]
            try:
                if timestamp > 1e12:  # Assume milliseconds
                    timestamp = timestamp / 1000
                dt = datetime.datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError, OverflowError) as e:
                logger.error("Error in data_inspector: %s", e)
                return f"Invalid timestamp: {timestamp}"
        return "Insufficient data"

    @staticmethod
    def _handle_windows_filetime(data: bytes) -> str:
        """Handle WINDOWS_FILETIME data type."""
        if len(data) >= 8:
            filetime = struct.unpack("<Q", data[:8])[0]
            try:
                timestamp = (filetime - 116444736000000000) / 10000000
                dt = datetime.datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError, OverflowError) as e:
                logger.error("Error in data_inspector: %s", e)
                return f"Invalid FILETIME: {filetime}"
        return "Insufficient data"

    @staticmethod
    def _handle_dos_datetime(data: bytes) -> str:
        """Handle DOS_DATETIME data type."""
        if len(data) >= 4:
            dos_time = struct.unpack("<H", data[:2])[0]
            dos_date = struct.unpack("<H", data[2:4])[0]
            try:
                year = ((dos_date >> 9) & 0x7F) + 1980
                month = (dos_date >> 5) & 0x0F
                day = dos_date & 0x1F
                hour = (dos_time >> 11) & 0x1F
                minute = (dos_time >> 5) & 0x3F
                second = (dos_time & 0x1F) * 2

                from datetime import timezone

                dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.UTC)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError) as e:
                logger.error("Error in data_inspector: %s", e)
                return f"Invalid DOS datetime: {dos_date:04X} {dos_time:04X}"
        return "Insufficient data"

    @staticmethod
    def _handle_binary(data: bytes) -> str:
        """Handle BINARY data type."""
        return " ".join(f"{_b:08b}" for _b in data[:8])

    @staticmethod
    def _handle_hex(data: bytes) -> str:
        """Handle HEX data type."""
        return " ".join(f"{_b:02X}" for _b in data[:16])

    @staticmethod
    def _handle_guid(data: bytes) -> str:
        """Handle GUID data type."""
        if len(data) >= 16:
            guid_parts = struct.unpack("<IHH8B", data[:16])
            return f"{guid_parts[0]:08X}-{guid_parts[1]:04X}-{guid_parts[2]:04X}-{guid_parts[3]:02X}{guid_parts[4]:02X}-" + "".join(
                f"{guid_parts[_i]:02X}" for _i in range(5, 11)
            )
        return "Insufficient data"

    @staticmethod
    def _handle_ipv4_address(data: bytes) -> str:
        """Handle IPV4_ADDRESS data type."""
        if len(data) >= 4:
            return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"
        return "Insufficient data"

    @staticmethod
    def _handle_ipv6_address(data: bytes) -> str:
        """Handle IPV6_ADDRESS data type."""
        if len(data) >= 16:
            parts = struct.unpack(">8H", data[:16])
            return ":".join(f"{_part:04x}" for _part in parts)
        return "Insufficient data"

    @staticmethod
    def _handle_mac_address(data: bytes) -> str:
        """Handle MAC_ADDRESS data type."""
        if len(data) >= 6:
            return ":".join(f"{_b:02X}" for _b in data[:6])
        return "Insufficient data"

    @staticmethod
    def interpret(data: bytes, data_type: DataType) -> str:
        """Interpret binary data as the specified data type.

        Args:
            data: Binary data to interpret
            data_type: Type to interpret the data as

        Returns:
            String representation of the interpreted data

        """
        if not data:
            return "No data"

        # Handler mapping dictionary
        handlers = {
            DataType.UINT8: DataInterpreter._handle_uint8,
            DataType.INT8: DataInterpreter._handle_int8,
            DataType.UINT16_LE: DataInterpreter._handle_uint16_le,
            DataType.UINT16_BE: DataInterpreter._handle_uint16_be,
            DataType.INT16_LE: DataInterpreter._handle_int16_le,
            DataType.INT16_BE: DataInterpreter._handle_int16_be,
            DataType.UINT32_LE: DataInterpreter._handle_uint32_le,
            DataType.UINT32_BE: DataInterpreter._handle_uint32_be,
            DataType.INT32_LE: DataInterpreter._handle_int32_le,
            DataType.INT32_BE: DataInterpreter._handle_int32_be,
            DataType.UINT64_LE: DataInterpreter._handle_uint64_le,
            DataType.UINT64_BE: DataInterpreter._handle_uint64_be,
            DataType.INT64_LE: DataInterpreter._handle_int64_le,
            DataType.INT64_BE: DataInterpreter._handle_int64_be,
            DataType.FLOAT32_LE: DataInterpreter._handle_float32_le,
            DataType.FLOAT32_BE: DataInterpreter._handle_float32_be,
            DataType.FLOAT64_LE: DataInterpreter._handle_float64_le,
            DataType.FLOAT64_BE: DataInterpreter._handle_float64_be,
            DataType.ASCII: DataInterpreter._handle_ascii,
            DataType.UTF8: DataInterpreter._handle_utf8,
            DataType.UTF16_LE: DataInterpreter._handle_utf16_le,
            DataType.UTF16_BE: DataInterpreter._handle_utf16_be,
            DataType.UNIX_TIMESTAMP_32: DataInterpreter._handle_unix_timestamp_32,
            DataType.UNIX_TIMESTAMP_64: DataInterpreter._handle_unix_timestamp_64,
            DataType.WINDOWS_FILETIME: DataInterpreter._handle_windows_filetime,
            DataType.DOS_DATETIME: DataInterpreter._handle_dos_datetime,
            DataType.BINARY: DataInterpreter._handle_binary,
            DataType.HEX: DataInterpreter._handle_hex,
            DataType.GUID: DataInterpreter._handle_guid,
            DataType.IPV4_ADDRESS: DataInterpreter._handle_ipv4_address,
            DataType.IPV6_ADDRESS: DataInterpreter._handle_ipv6_address,
            DataType.MAC_ADDRESS: DataInterpreter._handle_mac_address,
        }

        if handler := handlers.get(data_type):
            try:
                return handler(data)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Error interpreting data as %s: %s", data_type.value, e)
                return "Error interpreting data"

        return "Unsupported data type"


class DataInspector(QWidget if PYQT6_AVAILABLE else object):
    """Data inspector widget for interpreting selected bytes.

    This widget displays the selected bytes interpreted as various data types
    including integers, floats, strings, timestamps, and more.
    """

    #: Signal emitted when user wants to modify data (type: bytes)
    data_modified = pyqtSignal(bytes) if PYQT6_AVAILABLE else None

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the data inspector widget.

        Args:
            parent: Parent widget (default: None)

        """
        if not PYQT6_AVAILABLE:
            logger.warning("PyQt6 not available, DataInspector cannot be created")
            return

        super().__init__(parent)
        self.current_data: bytes = b""
        self.current_offset: int = 0

        # Initialize UI attributes
        self.integer_table: QTableWidget | None = None
        self.float_table: QTableWidget | None = None
        self.ascii_edit: QLineEdit | None = None
        self.utf8_edit: QLineEdit | None = None
        self.utf16le_edit: QLineEdit | None = None
        self.utf16be_edit: QLineEdit | None = None
        self.hex_edit: QLineEdit | None = None
        self.binary_edit: QLineEdit | None = None
        self.time_table: QTableWidget | None = None
        self.special_table: QTableWidget | None = None
        self.input_type_combo: QComboBox | None = None
        self.value_edit: QLineEdit | None = None
        self.apply_button: QPushButton | None = None
        self.clear_button: QPushButton | None = None
        self.offset_label: QLabel | None = None
        self.size_label: QLabel | None = None
        self.checksum_label: QLabel | None = None
        self.tab_widget: QTabWidget | None = None

        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the user interface.

        Initializes all UI components including tabs, tables, and input controls
        for data interpretation and modification.

        """
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Info section
        info_frame = QFrame()
        info_frame.setFrameStyle(QFrame.StyledPanel)
        info_layout = QFormLayout(info_frame)

        self.offset_label = QLabel("No selection")
        self.size_label = QLabel("0 bytes")
        self.checksum_label = QLabel("-")

        info_layout.addRow("Offset:", self.offset_label)
        info_layout.addRow("Size:", self.size_label)
        info_layout.addRow("Checksum:", self.checksum_label)

        layout.addWidget(info_frame)

        # Create tab widget for _different interpretation categories
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Integer tab
        self.create_integer_tab()

        # Float tab
        self.create_float_tab()

        # String tab
        self.create_string_tab()

        # Time tab
        self.create_time_tab()

        # Special tab
        self.create_special_tab()

        # Modification controls
        self.create_modification_controls()

    def create_integer_tab(self) -> None:
        """Create the integer interpretations tab.

        Initializes the integer interpretation tab with a table displaying
        various integer format interpretations (signed/unsigned, LE/BE).

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create table for integer values
        self.integer_table = QTableWidget(8, 3)
        self.integer_table.setHorizontalHeaderLabels(["Type", "Little Endian", "Big Endian"])
        self.integer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Set up rows
        integer_types = [
            ("8-bit unsigned", DataType.UINT8, None),
            ("8-bit signed", DataType.INT8, None),
            ("16-bit unsigned", DataType.UINT16_LE, DataType.UINT16_BE),
            ("16-bit signed", DataType.INT16_LE, DataType.INT16_BE),
            ("32-bit unsigned", DataType.UINT32_LE, DataType.UINT32_BE),
            ("32-bit signed", DataType.INT32_LE, DataType.INT32_BE),
            ("64-bit unsigned", DataType.UINT64_LE, DataType.UINT64_BE),
            ("64-bit signed", DataType.INT64_LE, DataType.INT64_BE),
        ]

        for i, (type_name, _, be_type) in enumerate(integer_types):
            self.integer_table.setItem(i, 0, QTableWidgetItem(type_name))
            self.integer_table.setItem(i, 1, QTableWidgetItem("-"))
            self.integer_table.setItem(i, 2, QTableWidgetItem("-" if be_type else "N/A"))

        layout.addWidget(self.integer_table)
        self.tab_widget.addTab(tab, "Integers")

    def create_float_tab(self) -> None:
        """Create the floating point interpretations tab.

        Initializes the floating-point interpretation tab with a table
        displaying 32-bit and 64-bit float interpretations in LE/BE formats.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create table for float values
        self.float_table = QTableWidget(2, 3)
        self.float_table.setHorizontalHeaderLabels(["Type", "Little Endian", "Big Endian"])
        self.float_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Set up rows
        float_types = ["32-bit float", "64-bit double"]
        for i, type_name in enumerate(float_types):
            self.float_table.setItem(i, 0, QTableWidgetItem(type_name))
            self.float_table.setItem(i, 1, QTableWidgetItem("-"))
            self.float_table.setItem(i, 2, QTableWidgetItem("-"))

        layout.addWidget(self.float_table)
        self.tab_widget.addTab(tab, "Floats")

    def create_string_tab(self) -> None:
        """Create the string interpretations tab.

        Initializes the string interpretation tab with input fields for ASCII,
        UTF-8, UTF-16 encodings and raw hex/binary representations.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # String interpretations
        string_group = QGroupBox("String Interpretations")
        string_layout = QFormLayout(string_group)

        self.ascii_edit = QLineEdit()
        self.ascii_edit.setReadOnly(True)
        string_layout.addRow("ASCII:", self.ascii_edit)

        self.utf8_edit = QLineEdit()
        self.utf8_edit.setReadOnly(True)
        string_layout.addRow("UTF-8:", self.utf8_edit)

        self.utf16le_edit = QLineEdit()
        self.utf16le_edit.setReadOnly(True)
        string_layout.addRow("UTF-16 LE:", self.utf16le_edit)

        self.utf16be_edit = QLineEdit()
        self.utf16be_edit.setReadOnly(True)
        string_layout.addRow("UTF-16 BE:", self.utf16be_edit)

        layout.addWidget(string_group)

        # Raw data display
        raw_group = QGroupBox("Raw Data")
        raw_layout = QFormLayout(raw_group)

        self.hex_edit = QLineEdit()
        self.hex_edit.setReadOnly(True)
        raw_layout.addRow("Hex:", self.hex_edit)

        self.binary_edit = QLineEdit()
        self.binary_edit.setReadOnly(True)
        raw_layout.addRow("Binary:", self.binary_edit)

        layout.addWidget(raw_group)
        self.tab_widget.addTab(tab, "Strings")

    def create_time_tab(self) -> None:
        """Create the time interpretations tab.

        Initializes the time interpretation tab with a table displaying various
        timestamp format interpretations (Unix, Windows FILETIME, DOS datetime).

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create table for time values
        self.time_table = QTableWidget(4, 2)
        self.time_table.setHorizontalHeaderLabels(["Type", "Value"])
        self.time_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Set up rows
        time_types = [
            "Unix Timestamp (32-bit)",
            "Unix Timestamp (64-bit)",
            "Windows FILETIME",
            "DOS Date/Time",
        ]

        for i, type_name in enumerate(time_types):
            self.time_table.setItem(i, 0, QTableWidgetItem(type_name))
            self.time_table.setItem(i, 1, QTableWidgetItem("-"))

        layout.addWidget(self.time_table)
        self.tab_widget.addTab(tab, "Time")

    def create_special_tab(self) -> None:
        """Create the special interpretations tab.

        Initializes the special interpretation tab with a table displaying
        special format interpretations (GUID, IPv4, IPv6, MAC address).

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Create table for special values
        self.special_table = QTableWidget(4, 2)
        self.special_table.setHorizontalHeaderLabels(["Type", "Value"])
        self.special_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Set up rows
        special_types = [
            "GUID",
            "IPv4 Address",
            "IPv6 Address",
            "MAC Address",
        ]

        for i, type_name in enumerate(special_types):
            self.special_table.setItem(i, 0, QTableWidgetItem(type_name))
            self.special_table.setItem(i, 1, QTableWidgetItem("-"))

        layout.addWidget(self.special_table)
        self.tab_widget.addTab(tab, "Special")

    def create_modification_controls(self) -> None:
        """Create controls for modifying data.

        Initializes the data modification section with input type selection,
        value input field, and apply/clear buttons for modifying selected data.

        """
        mod_frame = QFrame()
        mod_frame.setFrameStyle(QFrame.StyledPanel)
        mod_layout = QVBoxLayout(mod_frame)

        # Title
        title_label = QLabel("Modify Selected Data")
        title_label.setFont(QFont("", 9, QFont.Bold))
        mod_layout.addWidget(title_label)

        # Input controls
        input_layout = QHBoxLayout()

        self.input_type_combo = QComboBox()
        self.input_type_combo.addItems(
            [
                "Hex",
                "Decimal",
                "ASCII",
                "UTF-8",
                "Binary",
            ],
        )
        input_layout.addWidget(QLabel("Type:"))
        input_layout.addWidget(self.input_type_combo)

        mod_layout.addLayout(input_layout)

        # Value input
        value_layout = QHBoxLayout()
        self.value_edit = QLineEdit()
        self.value_edit.setText("")
        value_layout.addWidget(QLabel("Value:"))
        value_layout.addWidget(self.value_edit)

        mod_layout.addLayout(value_layout)

        # Buttons
        button_layout = QHBoxLayout()

        self.apply_button = QPushButton("Apply")
        self.apply_button.clicked.connect(self.apply_modification)
        self.apply_button.setEnabled(False)
        button_layout.addWidget(self.apply_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_modification)
        button_layout.addWidget(self.clear_button)

        button_layout.addStretch()
        mod_layout.addLayout(button_layout)

        # Connect signals
        self.value_edit.textChanged.connect(self.on_value_changed)

        self.layout().addWidget(mod_frame)

    def set_data(self, data: bytes, offset: int = 0) -> None:
        """Set the data to inspect.

        Args:
            data: Binary data to inspect
            offset: Starting offset of the data (default: 0)

        """
        self.current_data = data
        self.current_offset = offset
        self.update_display()

    def update_display(self) -> None:
        """Update all displays with current data.

        Refreshes all data interpretation tables, string displays, and
        modification controls based on the currently selected binary data.

        """
        if not self.current_data:
            self.clear_display()
            return

        # Update info section
        self.offset_label.setText(f"0x{self.current_offset:X}")
        self.size_label.setText(f"{len(self.current_data)} bytes")

        # Calculate checksum
        checksum = sum(self.current_data) & 0xFF
        self.checksum_label.setText(f"0x{checksum:02X}")

        # Update integer table
        self.update_integer_table()

        # Update float table
        self.update_float_table()

        # Update string displays
        self.update_string_displays()

        # Update time table
        self.update_time_table()

        # Update special table
        self.update_special_table()

        # Enable/disable modification controls
        self.apply_button.setEnabled(len(self.current_data) > 0)

    def update_integer_table(self) -> None:
        """Update the integer interpretations table.

        Interprets the current data as various integer formats and updates
        the integer table display.

        """
        integer_types = [
            (DataType.UINT8, None),
            (DataType.INT8, None),
            (DataType.UINT16_LE, DataType.UINT16_BE),
            (DataType.INT16_LE, DataType.INT16_BE),
            (DataType.UINT32_LE, DataType.UINT32_BE),
            (DataType.INT32_LE, DataType.INT32_BE),
            (DataType.UINT64_LE, DataType.UINT64_BE),
            (DataType.INT64_LE, DataType.INT64_BE),
        ]

        for i, (le_type, be_type) in enumerate(integer_types):
            # Little endian (or single value for 8-bit)
            le_value = DataInterpreter.interpret(self.current_data, le_type)
            self.integer_table.setItem(i, 1, QTableWidgetItem(le_value))

            # Big endian (if applicable)
            if be_type:
                be_value = DataInterpreter.interpret(self.current_data, be_type)
                self.integer_table.setItem(i, 2, QTableWidgetItem(be_value))
            else:
                self.integer_table.setItem(i, 2, QTableWidgetItem("N/A"))

    def update_float_table(self) -> None:
        """Update the floating point interpretations table.

        Interprets the current data as various floating-point formats and
        updates the float table display.

        """
        float_types = [
            (DataType.FLOAT32_LE, DataType.FLOAT32_BE),
            (DataType.FLOAT64_LE, DataType.FLOAT64_BE),
        ]

        for i, (le_type, be_type) in enumerate(float_types):
            le_value = DataInterpreter.interpret(self.current_data, le_type)
            be_value = DataInterpreter.interpret(self.current_data, be_type)

            self.float_table.setItem(i, 1, QTableWidgetItem(le_value))
            self.float_table.setItem(i, 2, QTableWidgetItem(be_value))

    def update_string_displays(self) -> None:
        """Update the string interpretation displays.

        Interprets the current data as various string encodings and raw
        formats, updating the respective display fields.

        """
        self.ascii_edit.setText(DataInterpreter.interpret(self.current_data, DataType.ASCII))
        self.utf8_edit.setText(DataInterpreter.interpret(self.current_data, DataType.UTF8))
        self.utf16le_edit.setText(DataInterpreter.interpret(self.current_data, DataType.UTF16_LE))
        self.utf16be_edit.setText(DataInterpreter.interpret(self.current_data, DataType.UTF16_BE))
        self.hex_edit.setText(DataInterpreter.interpret(self.current_data, DataType.HEX))
        self.binary_edit.setText(DataInterpreter.interpret(self.current_data, DataType.BINARY))

    def update_time_table(self) -> None:
        """Update the time interpretations table.

        Interprets the current data as various timestamp formats and updates
        the time table display.

        """
        time_types = [
            DataType.UNIX_TIMESTAMP_32,
            DataType.UNIX_TIMESTAMP_64,
            DataType.WINDOWS_FILETIME,
            DataType.DOS_DATETIME,
        ]

        for i, time_type in enumerate(time_types):
            value = DataInterpreter.interpret(self.current_data, time_type)
            self.time_table.setItem(i, 1, QTableWidgetItem(value))

    def update_special_table(self) -> None:
        """Update the special interpretations table.

        Interprets the current data as special types (GUID, IPv4, IPv6, MAC)
        and updates the special table display.

        """
        special_types = [
            DataType.GUID,
            DataType.IPV4_ADDRESS,
            DataType.IPV6_ADDRESS,
            DataType.MAC_ADDRESS,
        ]

        for i, special_type in enumerate(special_types):
            value = DataInterpreter.interpret(self.current_data, special_type)
            self.special_table.setItem(i, 1, QTableWidgetItem(value))

    def clear_display(self) -> None:
        """Clear all displays.

        Resets all interpretation tables and string displays to empty/default
        state when no data is selected.

        """
        self.offset_label.setText("No selection")
        self.size_label.setText("0 bytes")
        self.checksum_label.setText("-")

        # Clear tables
        for i in range(self.integer_table.rowCount()):
            self.integer_table.setItem(i, 1, QTableWidgetItem("-"))
            self.integer_table.setItem(i, 2, QTableWidgetItem("-"))

        for i in range(self.float_table.rowCount()):
            self.float_table.setItem(i, 1, QTableWidgetItem("-"))
            self.float_table.setItem(i, 2, QTableWidgetItem("-"))

        for i in range(self.time_table.rowCount()):
            self.time_table.setItem(i, 1, QTableWidgetItem("-"))

        for i in range(self.special_table.rowCount()):
            self.special_table.setItem(i, 1, QTableWidgetItem("-"))

        # Clear string displays
        self.ascii_edit.clear()
        self.utf8_edit.clear()
        self.utf16le_edit.clear()
        self.utf16be_edit.clear()
        self.hex_edit.clear()
        self.binary_edit.clear()

        self.apply_button.setEnabled(False)

    def on_value_changed(self) -> None:
        """Handle value input changes.

        Enables the apply button when valid input is present and data is selected.

        """
        text = self.value_edit.text().strip()
        self.apply_button.setEnabled(len(text) > 0 and len(self.current_data) > 0)

    def apply_modification(self) -> None:
        """Apply the modification to the selected data.

        Parses the user input based on the selected input type (Hex, Decimal,
        ASCII, UTF-8, Binary) and emits the data_modified signal with the
        converted bytes.

        Raises:
            ValueError: If the input format is invalid for the selected type

        """
        input_type = self.input_type_combo.currentText()
        value_text = self.value_edit.text().strip()

        if not value_text:
            return

        try:
            if input_type == "Hex":
                # Parse hex input
                hex_clean = value_text.replace(" ", "").replace("-", "")
                if len(hex_clean) % 2 != 0:
                    hex_clean = f"0{hex_clean}"
                new_data = bytes.fromhex(hex_clean)

            elif input_type == "Decimal":
                # Parse decimal input (assume single byte for now)
                # Validate and sanitize user input
                value_text = value_text.strip()
                if not value_text.isdigit():
                    error_msg = "Decimal value must contain only digits"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                value = int(value_text)
                if 0 <= value <= 255:
                    new_data = bytes([value])
                else:
                    error_msg = "Decimal value must be 0-255"
                    logger.error(error_msg)
                    raise ValueError(error_msg)

            elif input_type == "ASCII":
                new_data = value_text.encode("ascii", errors="replace")

            elif input_type == "UTF-8":
                new_data = value_text.encode("utf-8")

            elif input_type == "Binary":
                # Parse binary input
                binary_clean = value_text.replace(" ", "")
                if len(binary_clean) % 8 != 0:
                    # Pad with zeros
                    binary_clean = binary_clean.zfill((len(binary_clean) + 7) // 8 * 8)

                new_data = b""
                for i in range(0, len(binary_clean), 8):
                    byte_str = binary_clean[i : i + 8]
                    new_data += bytes([int(byte_str, 2)])

            else:
                return

            # Emit signal with new data
            if self.data_modified:
                self.data_modified.emit(new_data)

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error parsing input value: %s", e)

    def clear_modification(self) -> None:
        """Clear the modification input.

        Resets the value input field to empty state.

        """
        self.value_edit.clear()
