"""Miscellaneous utility functions for the Intellicrack framework.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import datetime
import logging
import re
from pathlib import Path
from typing import Any

# Module logger
logger = logging.getLogger(__name__)


def log_message(msg: str) -> str:
    """Return a timestamped log message.

    Create a consistently formatted log message with the current timestamp
    prefixed to the provided message text. Used throughout the application
    to ensure uniform log message formatting.

    Args:
        msg: The message text to be logged

    Returns:
        str: Formatted log message with timestamp prefix

    """
    return f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"


def get_timestamp(format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Get current timestamp as formatted string.

    Args:
        format_string: strftime format string

    Returns:
        str: Formatted timestamp

    """
    return datetime.datetime.now().strftime(format_string)


def format_bytes(size: int, precision: int = 2) -> str:
    """Format a byte size into a human-readable string.

    Args:
        size: Size in bytes
        precision: Number of decimal places

    Returns:
        str: Formatted size string (e.g., "1.23 MB")

    """
    for _unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.{precision}f} {_unit}"
        size /= 1024.0
    return f"{size:.{precision}f} PB"


def validate_path(path: str | Path, must_exist: bool = True) -> bool:
    """Validate a file or directory path.

    Args:
        path: Path to validate
        must_exist: Whether the path must exist

    Returns:
        bool: True if path is valid

    """
    try:
        path = Path(path)

        # Check if path is absolute
        if not path.is_absolute():
            logger.warning("Path is not absolute: %s", path)
            return False

        # Check existence if required
        if must_exist and not path.exists():
            logger.warning("Path does not exist: %s", path)
            return False

        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error validating path %s: %s", path, e)
        return False


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """Sanitize a filename by removing invalid characters.

    Args:
        filename: Original filename
        replacement: Character to replace invalid chars with

    Returns:
        str: Sanitized filename

    """
    # Define invalid characters for filenames
    invalid_chars = r'[<>:"/\\|?*]'

    # Replace invalid characters
    sanitized = re.sub(invalid_chars, replacement, filename)

    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(". ")

    # Ensure filename is not empty
    if not sanitized:
        sanitized = "unnamed"

    return sanitized


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        str: Truncated string

    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def safe_str(obj: Any, max_length: int = 100) -> str:
    """Safely convert an object to string with length limit.

    Args:
        obj: Object to convert
        max_length: Maximum string length

    Returns:
        str: String representation

    """
    try:
        result = str(obj)
        return truncate_string(result, max_length)
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in misc_utils: %s", e)
        return "<str_conversion_failed>"


def parse_size_string(size_str: str) -> int:
    """Parse a human-readable size string to bytes.

    Args:
        size_str: Size string (e.g., "10MB", "1.5GB")

    Returns:
        int: Size in bytes

    Raises:
        ValueError: If string cannot be parsed

    """
    units = {
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
        "PB": 1024**5,
    }

    # Remove spaces and convert to uppercase
    size_str = size_str.strip().upper()

    # Match number and unit
    match = re.match(r"^([\d.]+)\s*([KMGTP]?B)?$", size_str)
    if not match:
        raise ValueError(f"Invalid size string: {size_str}")

    number = float(match.group(1))
    unit = match.group(2) or "B"

    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")

    return int(number * units[unit])


def get_file_extension(file_path: str | Path, lower: bool = True) -> str:
    """Get file extension from path.

    Args:
        file_path: File path
        lower: Whether to convert to lowercase

    Returns:
        str: File extension (including dot)

    """
    path = Path(file_path)
    ext = path.suffix
    return ext.lower() if lower else ext


def ensure_directory_exists(directory: str | Path) -> bool:
    """Ensure a directory exists, creating it if necessary.

    Args:
        directory: Directory path

    Returns:
        bool: True if directory exists or was created

    """
    try:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to create directory %s: %s", directory, e)
        return False


def is_valid_ip_address(ip: str) -> bool:
    """Check if a string is a valid IP address.

    Args:
        ip: IP address string

    Returns:
        bool: True if valid IP

    """
    # IPv4 pattern
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$",
    )

    # IPv6 pattern (simplified)
    ipv6_pattern = re.compile(
        r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$",
    )

    if ipv4_pattern.match(ip):
        # Validate IPv4 octets
        octets = ip.split(".")
        return all(0 <= int(_octet) <= 255 for _octet in octets)

    return bool(ipv6_pattern.match(ip))


def is_valid_port(port: str | int) -> bool:
    """Check if a port number is valid.

    Args:
        port: Port number

    Returns:
        bool: True if valid port

    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError) as e:
        logger.error("Error in misc_utils: %s", e)
        return False


# Exported functions
__all__ = [
    "ensure_directory_exists",
    "format_bytes",
    "get_file_extension",
    "get_timestamp",
    "is_valid_ip_address",
    "is_valid_port",
    "log_message",
    "parse_size_string",
    "safe_str",
    "sanitize_filename",
    "truncate_string",
    "validate_path",
]
