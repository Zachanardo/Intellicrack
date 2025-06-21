"""
Hex Utilities

Utility functions for hex manipulation and display.
"""

import logging
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)


def create_hex_dump(data: Union[bytes, bytearray],
                   bytes_per_line: int = 16,
                   start_offset: int = 0) -> str:
    """
    Create a formatted hex dump of binary data.

    Args:
        data: Binary data to dump
        bytes_per_line: Number of bytes per line
        start_offset: Starting offset for display

    Returns:
        Formatted hex dump string
    """
    lines = []

    for i in range(0, len(data), bytes_per_line):
        # Offset
        offset = start_offset + i

        # Get chunk
        chunk = data[i:i + bytes_per_line]

        # Hex representation
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)

        # ASCII representation
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in chunk
        )

        # Format line
        line = f"{offset:08x}  {hex_part}  |{ascii_part}|"
        lines.append(line)

    return '\n'.join(lines)


def hex_to_bytes(hex_string: str) -> bytes:
    """
    Convert hex string to bytes, handling various formats.

    Args:
        hex_string: Hex string (supports spaces, 0x prefix, \\x format)

    Returns:
        Converted bytes
    """
    # Remove common formatting
    hex_string = hex_string.strip()
    hex_string = hex_string.replace(' ', '')
    hex_string = hex_string.replace('\\x', '')
    hex_string = hex_string.replace('0x', '')
    hex_string = hex_string.replace(',', '')

    # Convert to bytes
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        logger.error(f"Invalid hex string: {e}")
        raise


def bytes_to_hex(data: bytes,
                format_style: str = 'plain',
                uppercase: bool = False) -> str:
    """
    Convert bytes to hex string in various formats.

    Args:
        data: Binary data
        format_style: Output format ('plain', 'spaces', '0x', '\\x', 'c_array')
        uppercase: Use uppercase hex characters

    Returns:
        Formatted hex string
    """
    if uppercase:
        hex_str = data.hex().upper()
    else:
        hex_str = data.hex()

    if format_style == 'plain':
        return hex_str
    elif format_style == 'spaces':
        return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    elif format_style == '0x':
        return '0x' + hex_str
    elif format_style == '\\x':
        return '\\x'.join([''] + [hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
    elif format_style == 'c_array':
        hex_bytes = [f'0x{hex_str[i:i+2]}' for i in range(0, len(hex_str), 2)]
        return ', '.join(hex_bytes)
    else:
        return hex_str


def find_pattern(data: bytes, pattern: bytes, max_results: int = None) -> List[int]:
    """
    Find all occurrences of a pattern in data.

    Args:
        data: Data to search
        pattern: Pattern to find
        max_results: Maximum number of results to return

    Returns:
        List of offsets where pattern was found
    """
    results = []
    start = 0

    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break

        results.append(pos)
        start = pos + 1

        if max_results and len(results) >= max_results:
            break

    return results


def calculate_checksum(data: bytes, algorithm: str = 'sum8') -> int:
    """
    Calculate checksum of data.

    Args:
        data: Binary data
        algorithm: Checksum algorithm ('sum8', 'sum16', 'xor')

    Returns:
        Checksum value
    """
    if algorithm == 'sum8':
        return sum(data) & 0xFF
    elif algorithm == 'sum16':
        return sum(data) & 0xFFFF
    elif algorithm == 'xor':
        result = 0
        for byte in data:
            result ^= byte
        return result
    else:
        raise ValueError(f"Unknown checksum algorithm: {algorithm}")


def patch_bytes(data: bytearray, offset: int, patch_data: bytes) -> bool:
    """
    Patch bytes at specified offset.

    Args:
        data: Data to patch (modified in place)
        offset: Offset to patch at
        patch_data: Data to write

    Returns:
        True if successful
    """
    try:
        if offset < 0 or offset + len(patch_data) > len(data):
            logger.error("Patch offset out of bounds")
            return False

        data[offset:offset + len(patch_data)] = patch_data
        return True

    except Exception as e:
        logger.error(f"Failed to patch bytes: {e}")
        return False


def nop_range(data: bytearray, start: int, end: int, arch: str = 'x86') -> bool:
    """
    Fill range with NOP instructions.

    Args:
        data: Data to patch (modified in place)
        start: Start offset
        end: End offset
        arch: Architecture for NOP instruction

    Returns:
        True if successful
    """
    nop_bytes = {
        'x86': b'\x90',
        'x64': b'\x90',
        'arm': b'\x00\xf0\x20\xe3',
        'arm64': b'\x1f\x20\x03\xd5'
    }

    if arch not in nop_bytes:
        logger.error(f"Unknown architecture: {arch}")
        return False

    nop = nop_bytes[arch]
    length = end - start

    if length <= 0:
        logger.error("Invalid range")
        return False

    # Calculate number of NOPs needed
    nop_count = length // len(nop)
    remainder = length % len(nop)

    # Fill with NOPs
    patch_data = nop * nop_count

    # Handle remainder with single-byte NOPs if possible
    if remainder > 0:
        if arch in ['x86', 'x64']:
            patch_data += b'\x90' * remainder
        else:
            logger.warning(f"Cannot perfectly fill {remainder} bytes on {arch}")
            return False

    return patch_bytes(data, start, patch_data)


def compare_bytes(data1: bytes, data2: bytes, context: int = 3) -> List[Dict]:
    """
    Compare two byte sequences and find differences.

    Args:
        data1: First data
        data2: Second data
        context: Number of context bytes to show

    Returns:
        List of differences with context
    """
    differences = []
    min_len = min(len(data1), len(data2))

    i = 0
    while i < min_len:
        if data1[i] != data2[i]:
            # Found difference, capture context
            start = max(0, i - context)
            end = min(min_len, i + context + 1)

            diff = {
                'offset': i,
                'data1': data1[start:end],
                'data2': data2[start:end],
                'byte1': data1[i],
                'byte2': data2[i]
            }

            differences.append(diff)

            # Skip to end of this difference region
            while i < min_len and data1[i] != data2[i]:
                i += 1
        else:
            i += 1

    # Handle length differences
    if len(data1) != len(data2):
        differences.append({
            'offset': min_len,
            'type': 'length',
            'len1': len(data1),
            'len2': len(data2)
        })

    return differences


def format_address(address: int, width: int = 8) -> str:
    """
    Format address for display.

    Args:
        address: Address value
        width: Width in hex digits

    Returns:
        Formatted address string
    """
    return f"0x{address:0{width}x}"


def is_printable_ascii(data: bytes) -> bool:
    """
    Check if data contains only printable ASCII characters.

    Args:
        data: Data to check

    Returns:
        True if all bytes are printable ASCII
    """
    return all(32 <= b < 127 for b in data)


def detect_encoding(data: bytes) -> Optional[str]:
    """
    Try to detect the encoding of data.

    Args:
        data: Data to analyze

    Returns:
        Detected encoding name or None
    """
    # Check for UTF-8 BOM
    if data.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'

    # Check for UTF-16 BOM
    if data.startswith(b'\xff\xfe'):
        return 'utf-16-le'
    if data.startswith(b'\xfe\xff'):
        return 'utf-16-be'

    # Try to decode as various encodings
    encodings = ['utf-8', 'ascii', 'utf-16', 'latin-1']

    for encoding in encodings:
        try:
            data.decode(encoding)
            return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue

    return None
