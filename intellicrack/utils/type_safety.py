"""Type safety utilities for runtime validation.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

from typing import Any, TypeVar, cast

T = TypeVar("T")


def get_typed_item(
    data: dict[str, Any],
    key: str,
    expected_type: type[T],
    default: T | None = None,
) -> T:
    """Safely get an item from a dictionary with runtime type checking.

    Args:
        data: Dictionary to retrieve from
        key: Key to lookup
        expected_type: Expected type of the value
        default: Default value if key is missing

    Returns:
        The value with the guaranteed type.

    Raises:
        TypeError: If the value exists but is not of the expected type.
        KeyError: If key is missing and no default is provided.

    """
    if key not in data:
        if default is not None:
            return default
        # If default is None but T implies it can be None (e.g. T is Optional[int]),
        # we can't easily check that at runtime with just `expected_type: type[T]`.
        # So we assume if default is None explicitly passed, we return None.
        # But here default defaults to None.
        # Let's strictly raise KeyError if not found and default is not provided/set.
        # To distinguish "not provided" from "provided as None", we can use a sentinel.
        raise KeyError(f"Key '{key}' not found in data")

    val = data[key]
    
    # Handle None if expected_type allows it?
    # Python's isinstance(None, int) is False.
    # We will be strict: if expected_type is int, val must be int.
    if not isinstance(val, expected_type):
         # Allow float to int conversion for loose matching if strictly needed?
         # No, explicit is better.
         # Special case: bool is subclass of int, so isinstance(True, int) is True.
         # We might want to allow it or not. For now standard isinstance is fine.
         raise TypeError(f"Expected key '{key}' to be {expected_type.__name__}, got {type(val).__name__}")
    
    return val

def validate_type(value: Any, expected_type: type[T], name: str = "value") -> T:
    """Validate that a value is of the expected type.

    Args:
        value: The value to check
        expected_type: The expected type
        name: Name of the variable for error message

    Returns:
        The value cast to T.

    Raises:
        TypeError: If value is not of expected_type.

    """
    if not isinstance(value, expected_type):
        raise TypeError(f"Expected '{name}' to be {expected_type.__name__}, got {type(value).__name__}")
    return cast(expected_type, value)
