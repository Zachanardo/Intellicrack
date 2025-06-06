"""Common string and formatting utilities."""

from typing import List, Union


def format_bytes(size_bytes: int) -> str:
    """Format byte size in human readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def extract_ascii_strings(data: Union[bytes, bytearray], min_length: int = 4) -> List[str]:
    """
    Extract printable ASCII strings from binary data.
    
    Args:
        data: Binary data to extract strings from
        min_length: Minimum string length to include
        
    Returns:
        List of extracted strings
    """
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Add final string if valid
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings