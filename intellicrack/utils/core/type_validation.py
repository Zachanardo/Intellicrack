# Copyright (C) 2025 Zachary Flint
# Contact: zachary.flint@zachfx.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Runtime type validation utilities for Intellicrack.

This module provides common validation functions to ensure type safety
and prevent runtime errors in critical functions.
"""

import os
from typing import Any, Dict, Optional


def validate_file_path(
    path: Any,
    check_exists: bool = True,
    check_readable: bool = True,
    check_writable: bool = False,
    allow_empty: bool = False
) -> None:
    """
    Validate a file path parameter.

    Args:
        path: Path to validate
        check_exists: Whether to check if path exists
        check_readable: Whether to check read permissions
        check_writable: Whether to check write permissions
        allow_empty: Whether to allow empty paths

    Raises:
        TypeError: If path is not a valid path type
        ValueError: If path is empty or invalid
        FileNotFoundError: If path doesn't exist (when check_exists=True)
        PermissionError: If permissions are insufficient
    """
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise TypeError(f"path must be str, bytes, or PathLike, got {type(path).__name__}")

    path_str = str(path)

    if not allow_empty and not path_str.strip():
        raise ValueError("path cannot be empty or whitespace")

    if check_exists and not os.path.exists(path_str):
        raise FileNotFoundError(f"Path does not exist: {path_str}")

    if check_exists and not os.path.isfile(path_str):
        raise ValueError(f"Path is not a file: {path_str}")

    if check_readable and not os.access(path_str, os.R_OK):
        raise PermissionError(f"No read permission for: {path_str}")

    if check_writable and not os.access(path_str, os.W_OK):
        raise PermissionError(f"No write permission for: {path_str}")


def validate_integer_range(
    value: Any,
    name: str,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
    allow_negative: bool = True
) -> None:
    """
    Validate an integer parameter and its range.

    Args:
        value: Value to validate
        name: Parameter name for error messages
        min_value: Minimum allowed value (inclusive)
        max_value: Maximum allowed value (inclusive)
        allow_negative: Whether negative values are allowed

    Raises:
        TypeError: If value is not an integer
        ValueError: If value is out of range
    """
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")

    if not allow_negative and value < 0:
        raise ValueError(f"{name} cannot be negative, got {value}")

    if min_value is not None and value < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {value}")

    if max_value is not None and value > max_value:
        raise ValueError(f"{name} must be <= {max_value}, got {value}")


def validate_bytes_data(
    data: Any,
    name: str = "data",
    max_size: Optional[int] = None,
    min_size: Optional[int] = None,
    allow_empty: bool = True
) -> None:
    """
    Validate binary data parameter.

    Args:
        data: Data to validate
        name: Parameter name for error messages
        max_size: Maximum allowed size in bytes
        min_size: Minimum required size in bytes
        allow_empty: Whether empty data is allowed

    Raises:
        TypeError: If data is not bytes
        ValueError: If data size is invalid
    """
    if not isinstance(data, bytes):
        raise TypeError(f"{name} must be bytes, got {type(data).__name__}")

    if not allow_empty and len(data) == 0:
        raise ValueError(f"{name} cannot be empty")

    if min_size is not None and len(data) < min_size:
        raise ValueError(f"{name} must be at least {min_size} bytes, got {len(data)}")

    if max_size is not None and len(data) > max_size:
        raise ValueError(f"{name} too large: {len(data)} bytes. Maximum: {max_size}")


def validate_string_list(
    strings: Any,
    name: str = "strings",
    allow_empty_list: bool = False,
    allow_empty_strings: bool = False,
    max_length: Optional[int] = None
) -> None:
    """
    Validate a list of strings parameter.

    Args:
        strings: List to validate
        name: Parameter name for error messages
        allow_empty_list: Whether empty lists are allowed
        allow_empty_strings: Whether empty strings in the list are allowed
        max_length: Maximum number of strings allowed

    Raises:
        TypeError: If not a list or contains non-strings
        ValueError: If list is invalid
    """
    if not isinstance(strings, list):
        raise TypeError(f"{name} must be list, got {type(strings).__name__}")

    if not allow_empty_list and len(strings) == 0:
        raise ValueError(f"{name} cannot be empty")

    if max_length is not None and len(strings) > max_length:
        raise ValueError(f"{name} too long: {len(strings)} items. Maximum: {max_length}")

    for i, item in enumerate(strings):
        if not isinstance(item, str):
            raise TypeError(f"{name}[{i}] must be str, got {type(item).__name__}")

        if not allow_empty_strings and not item.strip():
            raise ValueError(f"{name}[{i}] cannot be empty or whitespace")


def validate_memory_address(
    address: Any,
    name: str = "address",
    allow_zero: bool = False
) -> None:
    """
    Validate a memory address parameter.

    Args:
        address: Address to validate
        name: Parameter name for error messages
        allow_zero: Whether zero addresses are allowed

    Raises:
        TypeError: If address is not an integer
        ValueError: If address is invalid
    """
    if not isinstance(address, int):
        raise TypeError(f"{name} must be int, got {type(address).__name__}")

    if not allow_zero and address == 0:
        raise ValueError(f"{name} cannot be zero (null pointer)")

    if address < 0:
        raise ValueError(f"{name} cannot be negative, got {address}")

    # Check for reasonable address ranges (64-bit systems)
    max_address = (1 << 48) - 1  # 48-bit virtual address space
    if address > max_address:
        raise ValueError(f"{name} too large: 0x{address:x}. Maximum: 0x{max_address:x}")


def validate_process_id(pid: Any, name: str = "pid") -> None:
    """
    Validate a process ID parameter.

    Args:
        pid: Process ID to validate
        name: Parameter name for error messages

    Raises:
        TypeError: If PID is not an integer
        ValueError: If PID is invalid
    """
    if not isinstance(pid, int):
        raise TypeError(f"{name} must be int, got {type(pid).__name__}")

    if pid <= 0:
        raise ValueError(f"{name} must be positive, got {pid}")

    # Maximum PID on most systems is around 4 million
    if pid > 4194304:
        raise ValueError(f"{name} too large: {pid}. Maximum: 4194304")


def create_error_result(error_msg: str, result_template: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standardized error result dictionary.

    Args:
        error_msg: Error message
        result_template: Template with default values

    Returns:
        Dictionary with error information
    """
    if result_template is None:
        result_template = {"error": None}

    result = result_template.copy()
    result["error"] = error_msg
    return result
