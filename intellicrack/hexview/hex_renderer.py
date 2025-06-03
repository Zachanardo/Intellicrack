"""
Hex data rendering module for the hex viewer/editor.

This module provides classes for rendering binary data in various formats:
- Traditional hex view (offset | hex bytes | ASCII)
- Decimal view
- Binary view
- Structure-based view
"""

import re
import struct
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple


class ViewMode(Enum):
    """Enum for different view modes."""
    HEX = auto()
    DECIMAL = auto()
    BINARY = auto()
    STRUCTURE = auto()

    @classmethod
    def names(cls) -> List[str]:
        """Get a list of all view mode names."""
        return [mode.name.capitalize() for mode in cls]


class HexViewRenderer:
    """
    Handles rendering of binary data in various formats.
    
    This class is responsible for converting raw binary data into formatted
    text for display in the hex viewer.
    """

    def __init__(self, bytes_per_row: int = 16, group_size: int = 1,
                 show_ascii: bool = True, show_address: bool = True):
        """
        Initialize the hex view renderer.
        
        Args:
            bytes_per_row: Number of bytes to display per row
            group_size: Number of bytes to group together (1, 2, 4, or 8)
            show_ascii: Whether to show ASCII representation
            show_address: Whether to show address/offset column
        """
        self.bytes_per_row = bytes_per_row
        self.group_size = group_size
        self.show_ascii = show_ascii
        self.show_address = show_address

        # Validate and adjust the group_size
        if group_size not in (1, 2, 4, 8):
            self.group_size = 1

        # Ensure bytes_per_row is a multiple of group_size
        if self.bytes_per_row % self.group_size != 0:
            self.bytes_per_row = (self.bytes_per_row // self.group_size) * self.group_size
            if self.bytes_per_row == 0:
                self.bytes_per_row = self.group_size

    def set_bytes_per_row(self, bytes_per_row: int):
        """
        Set the number of bytes per row.
        
        Args:
            bytes_per_row: Number of bytes to display per row
        """
        if bytes_per_row > 0:
            # Ensure bytes_per_row is a multiple of group_size
            self.bytes_per_row = (bytes_per_row // self.group_size) * self.group_size
            if self.bytes_per_row == 0:
                self.bytes_per_row = self.group_size

    def set_group_size(self, group_size: int):
        """
        Set the group size for byte grouping.
        
        Args:
            group_size: Number of bytes to group together (1, 2, 4, or 8)
        """
        if group_size in (1, 2, 4, 8):
            self.group_size = group_size
            # Adjust bytes_per_row to be a multiple of group_size
            self.bytes_per_row = (self.bytes_per_row // self.group_size) * self.group_size
            if self.bytes_per_row == 0:
                self.bytes_per_row = self.group_size

    def render_hex_view(self, data: bytes, offset: int = 0,
                        highlight_ranges: Optional[List[Tuple[int, int, str]]] = None) -> str:
        """
        Render data in traditional hex view format.
        
        Args:
            data: Binary data to render
            offset: Starting offset of the data
            highlight_ranges: List of (start, end, color) tuples for highlighting
            
        Returns:
            Formatted hex view string
        """
        if not data:
            return "Empty data"

        result = []

        for i in range(0, len(data), self.bytes_per_row):
            # Extract the chunk for this row
            chunk = data[i:i + self.bytes_per_row]
            line_offset = offset + i

            # Start with the address/offset
            if self.show_address:
                line = f"{line_offset:08X}: "
            else:
                line = ""

            # Process the hex part based on grouping
            hex_parts = []
            for j in range(0, len(chunk), self.group_size):
                group = chunk[j:j + self.group_size]

                # Format the group based on its size
                if self.group_size == 1:
                    hex_parts.append(f"{group[0]:02X}")
                elif self.group_size == 2 and len(group) == 2:
                    hex_parts.append(f"{group[0]:02X}{group[1]:02X}")
                elif self.group_size == 4 and len(group) == 4:
                    hex_parts.append(f"{group[0]:02X}{group[1]:02X}{group[2]:02X}{group[3]:02X}")
                elif self.group_size == 8 and len(group) == 8:
                    hex_parts.append(f"{group[0]:02X}{group[1]:02X}{group[2]:02X}{group[3]:02X}"
                                     f"{group[4]:02X}{group[5]:02X}{group[6]:02X}{group[7]:02X}")
                else:
                    # Handle incomplete groups at the end
                    hex_parts.append("".join(f"{b:02X}" for b in group))

            # Join hex parts with spaces
            hex_str = " ".join(hex_parts)

            # Add padding to align ASCII part if needed
            hex_width = (self.bytes_per_row // self.group_size) * (self.group_size * 2 + 1) - 1
            padding = " " * (hex_width - len(hex_str))
            line += hex_str + padding

            # Add ASCII part if enabled
            if self.show_ascii:
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                line += " | " + ascii_part

            result.append(line)

        return "\n".join(result)

    def render_decimal_view(self, data: bytes, offset: int = 0) -> str:
        """
        Render data in decimal view format.
        
        Args:
            data: Binary data to render
            offset: Starting offset of the data
            
        Returns:
            Formatted decimal view string
        """
        if not data:
            return "Empty data"

        result = []

        for i in range(0, len(data), self.bytes_per_row):
            # Extract the chunk for this row
            chunk = data[i:i + self.bytes_per_row]
            line_offset = offset + i

            # Start with the address/offset
            if self.show_address:
                line = f"{line_offset:08d}: "
            else:
                line = ""

            # Process the decimal part based on grouping
            dec_parts = []
            for j in range(0, len(chunk), self.group_size):
                group = chunk[j:j + self.group_size]

                # Format the group based on its size
                if self.group_size == 1:
                    dec_parts.append(f"{group[0]:3d}")
                elif self.group_size == 2 and len(group) == 2:
                    val = (group[1] << 8) | group[0]
                    dec_parts.append(f"{val:5d}")
                elif self.group_size == 4 and len(group) == 4:
                    val = (group[3] << 24) | (group[2] << 16) | (group[1] << 8) | group[0]
                    dec_parts.append(f"{val:10d}")
                elif self.group_size == 8 and len(group) == 8:
                    val = ((group[7] << 56) | (group[6] << 48) | (group[5] << 40) | (group[4] << 32) |
                           (group[3] << 24) | (group[2] << 16) | (group[1] << 8) | group[0])
                    dec_parts.append(f"{val:20d}")
                else:
                    # Handle incomplete groups at the end
                    dec_parts.append(" ".join(f"{b:3d}" for b in group))

            # Join decimal parts with spaces
            line += " ".join(dec_parts)

            # Add ASCII part if enabled
            if self.show_ascii:
                # Add padding to align ASCII part
                padding = " " * (self.bytes_per_row * 4 - len(line) + (8 if self.show_address else 0))
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                line += padding + " | " + ascii_part

            result.append(line)

        return "\n".join(result)

    def render_binary_view(self, data: bytes, offset: int = 0) -> str:
        """
        Render data in binary view format.
        
        Args:
            data: Binary data to render
            offset: Starting offset of the data
            
        Returns:
            Formatted binary view string
        """
        if not data:
            return "Empty data"

        result = []

        # For binary view, we might want fewer bytes per row due to display width
        bytes_per_binary_row = min(self.bytes_per_row, 8)

        for i in range(0, len(data), bytes_per_binary_row):
            # Extract the chunk for this row
            chunk = data[i:i + bytes_per_binary_row]
            line_offset = offset + i

            # Start with the address/offset
            if self.show_address:
                line = f"{line_offset:08X}: "
            else:
                line = ""

            # Process the binary part
            bin_parts = []
            for b in chunk:
                bin_parts.append(f"{b:08b}")

            # Join binary parts with spaces
            line += " ".join(bin_parts)

            # Add ASCII part if enabled
            if self.show_ascii:
                # Add padding to align ASCII part
                padding = " " * (bytes_per_binary_row * 9 - len(" ".join(bin_parts)))
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                line += padding + " | " + ascii_part

            result.append(line)

        return "\n".join(result)

    def render_structure_view(self, data: bytes, structure_def: Dict[str, Any],
                             offset: int = 0) -> str:
        """
        Render data according to a structure definition.
        
        Args:
            data: Binary data to render
            structure_def: Structure definition including field types and sizes
            offset: Starting offset of the data
            
        Returns:
            Formatted structure view string
        """
        if not data or not structure_def:
            return "No data or structure definition"

        result = []
        current_offset = 0

        # Add header
        result.append("Offset      | Type     | Name                 | Value")
        result.append("-----------+----------+----------------------+-------------------------")

        # Process each field in the structure
        for field_name, field_info in structure_def.items():
            field_type = field_info.get('type', 'uint8')
            field_size = field_info.get('size', 1)
            field_count = field_info.get('count', 1)

            field_offset = offset + current_offset

            # Get the field data
            if current_offset + field_size * field_count <= len(data):
                field_data = data[current_offset:current_offset + field_size * field_count]

                # Format value based on type
                value = self._format_field_value(field_data, field_type, field_count)

                # Add to result
                line = f"0x{field_offset:08X} | {field_type:<8} | {field_name:<20} | {value}"
                result.append(line)

                # Move to next field
                current_offset += field_size * field_count
            else:
                # Not enough data for this field
                line = f"0x{field_offset:08X} | {field_type:<8} | {field_name:<20} | <insufficient data>"
                result.append(line)
                break

        return "\n".join(result)

    def _format_field_value(self, data: bytes, field_type: str, count: int) -> str:
        """Format a field value based on its type and count."""
        try:
            if count > 1:
                # Handle array types
                if field_type == 'char' and count > 0:
                    # Try to decode as a string
                    try:
                        # Find null terminator
                        null_pos = data.find(0)
                        if null_pos >= 0:
                            return f'"{data[:null_pos].decode("ascii", errors="replace")}"'
                        else:
                            return f'"{data.decode("ascii", errors="replace")}"'
                    except:
                        return " ".join(f"{b:02X}" for b in data)

                # Other array types
                results = []
                element_size = len(data) // count

                for i in range(count):
                    element_data = data[i * element_size:(i + 1) * element_size]
                    results.append(self._format_field_value(element_data, field_type, 1))

                return "[" + ", ".join(results) + "]"

            # Handle various scalar types
            if field_type == 'uint8':
                return f"{data[0]} (0x{data[0]:02X})"
            elif field_type == 'int8':
                val = struct.unpack('b', data)[0]
                return f"{val} (0x{data[0]:02X})"
            elif field_type == 'uint16':
                val = struct.unpack('<H', data)[0]
                return f"{val} (0x{val:04X})"
            elif field_type == 'int16':
                val = struct.unpack('<h', data)[0]
                return f"{val} (0x{val & 0xFFFF:04X})"
            elif field_type == 'uint32':
                val = struct.unpack('<I', data)[0]
                return f"{val} (0x{val:08X})"
            elif field_type == 'int32':
                val = struct.unpack('<i', data)[0]
                return f"{val} (0x{val & 0xFFFFFFFF:08X})"
            elif field_type == 'uint64':
                val = struct.unpack('<Q', data)[0]
                return f"{val} (0x{val:016X})"
            elif field_type == 'int64':
                val = struct.unpack('<q', data)[0]
                return f"{val} (0x{val & 0xFFFFFFFFFFFFFFFF:016X})"
            elif field_type == 'float':
                val = struct.unpack('<f', data)[0]
                return f"{val}"
            elif field_type == 'double':
                val = struct.unpack('<d', data)[0]
                return f"{val}"
            elif field_type == 'char':
                c = chr(data[0]) if 32 <= data[0] <= 126 else '.'
                return f"'{c}' (0x{data[0]:02X})"
            else:
                # Default to hex representation
                return " ".join(f"{b:02X}" for b in data)
        except Exception as e:
            return f"<error: {str(e)}>"


def parse_hex_view(hex_view: str, bytes_per_row: int = 16, offset_radix: int = 16) -> Tuple[int, bytes]:
    """
    Parse a hex view string back to binary data.
    
    Args:
        hex_view: Formatted hex view string to parse
        bytes_per_row: Number of bytes per row in the view
        offset_radix: Radix of the offset column (16 for hex, 10 for decimal)
        
    Returns:
        Tuple of (starting_offset, binary_data)
    """
    result = bytearray()
    start_offset = None

    # Define a regex for matching offset and hex data
    if offset_radix == 16:
        line_pattern = re.compile(r'^([0-9A-Fa-f]+):\s+((?:[0-9A-Fa-f]{2}\s*)+)')
    else:
        line_pattern = re.compile(r'^(\d+):\s+((?:[0-9A-Fa-f]{2}\s*)+)')

    for line in hex_view.splitlines():
        match = line_pattern.match(line)
        if match:
            # Extract offset and hex data
            offset_str, hex_data_str = match.groups()

            # Parse offset
            offset = int(offset_str, offset_radix)
            if start_offset is None:
                start_offset = offset

            # Parse hex data
            hex_values = re.findall(r'[0-9A-Fa-f]{2}', hex_data_str)
            for hex_val in hex_values:
                result.append(int(hex_val, 16))

    return (start_offset or 0, bytes(result))
