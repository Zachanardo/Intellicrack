#!/usr/bin/env python3
"""Refactor the interpret method in data_inspector.py to reduce complexity."""


def refactor_interpret_method():
    """Refactor the interpret method to use a handler dictionary."""

    file_path = 'intellicrack/hexview/data_inspector.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # New handler methods to add before the interpret method
    handler_methods = '''
    @staticmethod
    def _handle_uint8(data: bytes) -> str:
        """Handle UINT8 data type."""
        if len(data) >= 1:
            return str(data[0])
        return "Insufficient data"

    @staticmethod
    def _handle_int8(data: bytes) -> str:
        """Handle INT8 data type."""
        if len(data) >= 1:
            return str(struct.unpack("b", data[:1])[0])
        return "Insufficient data"

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
            null_pos = data.find(b"\\x00")
            if null_pos >= 0:
                text_data = data[:null_pos]
            else:
                text_data = data
            return text_data.decode("ascii", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid ASCII"

    @staticmethod
    def _handle_utf8(data: bytes) -> str:
        """Handle UTF8 data type."""
        try:
            null_pos = data.find(b"\\x00")
            if null_pos >= 0:
                text_data = data[:null_pos]
            else:
                text_data = data
            return text_data.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid UTF-8"

    @staticmethod
    def _handle_utf16_le(data: bytes) -> str:
        """Handle UTF16_LE data type."""
        try:
            null_pos = data.find(b"\\x00\\x00")
            if null_pos >= 0 and null_pos % 2 == 0:
                text_data = data[:null_pos]
            else:
                text_data = data
            return text_data.decode("utf-16le", errors="replace")
        except (UnicodeDecodeError, AttributeError) as e:
            logger.error("Error in data_inspector: %s", e)
            return "Invalid UTF-16 LE"

    @staticmethod
    def _handle_utf16_be(data: bytes) -> str:
        """Handle UTF16_BE data type."""
        try:
            null_pos = data.find(b"\\x00\\x00")
            if null_pos >= 0 and null_pos % 2 == 0:
                text_data = data[:null_pos]
            else:
                text_data = data
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

                dt = datetime.datetime(year, month, day, hour, minute, second)
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
            return (
                f"{guid_parts[0]:08X}-{guid_parts[1]:04X}-{guid_parts[2]:04X}-"
                f"{guid_parts[3]:02X}{guid_parts[4]:02X}-"
                + "".join(f"{guid_parts[_i]:02X}" for _i in range(5, 11))
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
'''

    # New simplified interpret method
    new_interpret_method = '''
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

        # Get the handler for this data type
        handler = handlers.get(data_type)
        if handler:
            try:
                return handler(data)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Error interpreting data as %s: %s", data_type.value, e)
                return "Error interpreting data"

        return "Unsupported data type"
'''

    # Find the location to insert the handler methods
    class_start = content.find('class DataInterpreter:')
    interpret_start = content.find('    def interpret(data: bytes, data_type: DataType) -> str:')

    if class_start == -1 or interpret_start == -1:
        print("Could not find DataInterpreter class or interpret method")
        return

    # Find the end of the interpret method
    interpret_end = content.find('\n\nclass DataInspector', interpret_start)
    if interpret_end == -1:
        interpret_end = content.find('\n\n\nclass', interpret_start)

    # Insert the handler methods before the interpret method
    new_content = (
        content[:interpret_start] +
        handler_methods + '\n' +
        new_interpret_method +
        content[interpret_end:]
    )

    # Write the refactored content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Refactored interpret method in {file_path}")
    print("Complexity reduced from 74 to approximately 5")

if __name__ == "__main__":
    refactor_interpret_method()
