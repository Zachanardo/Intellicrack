"""Type safety utilities for runtime validation.

This module provides runtime type checking and validation functions for
ensuring type safety when working with dynamic data structures and kwargs.

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

    Retrieves a value from the dictionary and verifies it matches the
    expected type. Raises TypeError if the value exists but has an
    unexpected type, or KeyError if the key is missing and no default
    is provided.

    Args:
        data: Dictionary to retrieve from.
        key: Key to lookup in the dictionary.
        expected_type: Expected type of the value.
        default: Default value if key is missing. Defaults to None.

    Returns:
        The value cast to type T with guaranteed type match.

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
        raise TypeError(f"Expected key '{key}' to be {expected_type.__name__}, got {type(val).__name__}")

    return val


def validate_type[T](value: Any, expected_type: type[T], name: str = "value") -> T:
    """Validate that a value is of the expected type.

    Checks if a value is an instance of the expected type and raises
    TypeError if not. Used for runtime type validation during execution.

    Args:
        value: The value to check.
        expected_type: The expected type to validate against.
        name: Name of the variable for error message. Defaults to "value".

    Returns:
        The value cast to type T if validation succeeds.

    Raises:
        TypeError: If value is not an instance of expected_type.

    """
    if not isinstance(value, expected_type):
        raise TypeError(f"Expected '{name}' to be {expected_type.__name__}, got {type(value).__name__}")
    return value


def get_kwarg_typed(
    kwargs: dict[str, object],
    key: str,
    expected_type: type[T],
    default: T,
) -> T:
    """Safely extract a typed value from kwargs with validation.

    Retrieves a value from kwargs dictionary and validates its type.
    Returns the default value if the key is missing, or the validated
    value if present and type-correct.

    Args:
        kwargs: The keyword arguments dictionary to extract from.
        key: Key to retrieve from kwargs.
        expected_type: Expected type of the value.
        default: Default value if key is missing. Also determines type T.

    Returns:
        The validated value if key exists and type matches, or default.

    Raises:
        TypeError: If value exists but is not of expected_type.

    """
    value = kwargs.get(key, default)
    if value is default:
        return default
    if not isinstance(value, expected_type):
        raise TypeError(f"Kwarg '{key}' expected {expected_type.__name__}, got {type(value).__name__}")
    return value


def ensure_dict(value: object, name: str = "value") -> dict[str, Any]:
    """Ensure a value is a dict, raising TypeError if not.

    Validates that a value is a dictionary instance and returns it.
    Raises TypeError with a descriptive message if validation fails.

    Args:
        value: Value to check.
        name: Name for error message. Defaults to "value".

    Returns:
        The value cast to dict[str, Any] if validation succeeds.

    Raises:
        TypeError: If value is not a dict.

    """
    if not isinstance(value, dict):
        raise TypeError(f"Expected '{name}' to be dict, got {type(value).__name__}")
    return cast("dict[str, Any]", value)


def ensure_list(value: object, name: str = "value") -> list[Any]:
    """Ensure a value is a list, raising TypeError if not.

    Validates that a value is a list instance and returns it.
    Raises TypeError with a descriptive message if validation fails.

    Args:
        value: Value to check.
        name: Name for error message. Defaults to "value".

    Returns:
        The value cast to list[Any] if validation succeeds.

    Raises:
        TypeError: If value is not a list.

    """
    if not isinstance(value, list):
        raise TypeError(f"Expected '{name}' to be list, got {type(value).__name__}")
    return value
