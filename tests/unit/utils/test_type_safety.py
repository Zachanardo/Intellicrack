"""Unit tests for type safety utilities.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

import pytest
from intellicrack.utils.type_safety import get_typed_item, validate_type


def test_validate_type_success():
    """Test successful type validation."""
    assert validate_type(123, int) == 123
    assert validate_type("test", str) == "test"
    assert validate_type({"a": 1}, dict) == {"a": 1}
    assert validate_type([1, 2], list) == [1, 2]


def test_validate_type_failure():
    """Test type validation failure."""
    with pytest.raises(TypeError, match="Expected 'value' to be str, got int"):
        validate_type(123, str)
    
    with pytest.raises(TypeError, match="Expected 'my_var' to be int, got str"):
        validate_type("123", int, name="my_var")


def test_get_typed_item_success():
    """Test successful typed item retrieval."""
    data = {"count": 10, "name": "analyzer", "active": True}
    
    assert get_typed_item(data, "count", int) == 10
    assert get_typed_item(data, "name", str) == "analyzer"
    assert get_typed_item(data, "active", bool) is True


def test_get_typed_item_default():
    """Test get_typed_item with default values."""
    data = {"count": 10}
    
    assert get_typed_item(data, "missing", int, default=5) == 5
    assert get_typed_item(data, "missing", str, default="none") == "none"


def test_get_typed_item_key_error():
    """Test get_typed_item missing key without default."""
    data = {"count": 10}
    
    with pytest.raises(KeyError, match="Key 'missing' not found in data"):
        get_typed_item(data, "missing", int)


def test_get_typed_item_type_error():
    """Test get_typed_item with wrong value type."""
    data = {"count": "10"}
    
    with pytest.raises(TypeError, match="Expected key 'count' to be int, got str"):
        get_typed_item(data, "count", int)
