"""Unit tests for type safety utilities.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

import pytest
from intellicrack.utils.type_safety import (
    ensure_dict,
    ensure_list,
    get_kwarg_typed,
    get_typed_item,
    validate_type,
)


def test_validate_type_success() -> None:
    """Test successful type validation."""
    assert validate_type(123, int) == 123
    assert validate_type("test", str) == "test"
    assert validate_type({"a": 1}, dict) == {"a": 1}
    assert validate_type([1, 2], list) == [1, 2]


def test_validate_type_failure() -> None:
    """Test type validation failure."""
    with pytest.raises(TypeError, match="Expected 'value' to be str, got int"):
        validate_type(123, str)
    
    with pytest.raises(TypeError, match="Expected 'my_var' to be int, got str"):
        validate_type("123", int, name="my_var")


def test_get_typed_item_success() -> None:
    """Test successful typed item retrieval."""
    data = {"count": 10, "name": "analyzer", "active": True}
    
    assert get_typed_item(data, "count", int) == 10
    assert get_typed_item(data, "name", str) == "analyzer"
    assert get_typed_item(data, "active", bool) is True


def test_get_typed_item_default() -> None:
    """Test get_typed_item with default values."""
    data = {"count": 10}
    
    assert get_typed_item(data, "missing", int, default=5) == 5
    assert get_typed_item(data, "missing", str, default="none") == "none"


def test_get_typed_item_key_error() -> None:
    """Test get_typed_item missing key without default."""
    data = {"count": 10}
    
    with pytest.raises(KeyError, match="Key 'missing' not found in data"):
        get_typed_item(data, "missing", int)


def test_get_typed_item_type_error() -> None:
    """Test get_typed_item with wrong value type."""
    data = {"count": "10"}

    with pytest.raises(TypeError, match="Expected key 'count' to be int, got str"):
        get_typed_item(data, "count", int)


class TestGetKwargTyped:
    """Tests for get_kwarg_typed function."""

    def test_returns_value_when_correct_type(self) -> None:
        """Test that get_kwarg_typed returns value when type matches."""
        kwargs: dict[str, object] = {"device": "cuda", "batch_size": 32}

        assert get_kwarg_typed(kwargs, "device", str, "cpu") == "cuda"
        assert get_kwarg_typed(kwargs, "batch_size", int, 16) == 32

    def test_returns_default_when_key_missing(self) -> None:
        """Test that get_kwarg_typed returns default for missing keys."""
        kwargs: dict[str, object] = {"device": "cuda"}

        assert get_kwarg_typed(kwargs, "batch_size", int, 16) == 16
        assert get_kwarg_typed(kwargs, "enabled", bool, True) is True

    def test_raises_typeerror_when_wrong_type(self) -> None:
        """Test that get_kwarg_typed raises TypeError for wrong types."""
        kwargs: dict[str, object] = {"device": 123, "enabled": "yes"}

        with pytest.raises(TypeError, match="Kwarg 'device' expected str, got int"):
            get_kwarg_typed(kwargs, "device", str, "cpu")

        with pytest.raises(TypeError, match="Kwarg 'enabled' expected bool, got str"):
            get_kwarg_typed(kwargs, "enabled", bool, False)

    def test_returns_default_when_value_is_default(self) -> None:
        """Test identity check with default value."""
        kwargs: dict[str, object] = {"cpu": "cpu"}
        assert get_kwarg_typed(kwargs, "device", str, "cpu") == "cpu"


class TestEnsureDict:
    """Tests for ensure_dict function."""

    def test_returns_dict_unchanged(self) -> None:
        """Test that ensure_dict returns dict values unchanged."""
        data = {"key": "value", "count": 42}
        result = ensure_dict(data)
        assert result == data
        assert result is data

    def test_works_with_empty_dict(self) -> None:
        """Test ensure_dict with empty dict."""
        result = ensure_dict({})
        assert result == {}

    def test_raises_typeerror_for_non_dict(self) -> None:
        """Test that ensure_dict raises TypeError for non-dict values."""
        with pytest.raises(TypeError, match="Expected 'value' to be dict, got list"):
            ensure_dict([1, 2, 3])

        with pytest.raises(TypeError, match="Expected 'value' to be dict, got str"):
            ensure_dict("not a dict")

        with pytest.raises(TypeError, match="Expected 'value' to be dict, got NoneType"):
            ensure_dict(None)

    def test_custom_name_in_error_message(self) -> None:
        """Test ensure_dict uses custom name in error message."""
        with pytest.raises(TypeError, match="Expected 'my_config' to be dict, got int"):
            ensure_dict(42, name="my_config")


class TestEnsureList:
    """Tests for ensure_list function."""

    def test_returns_list_unchanged(self) -> None:
        """Test that ensure_list returns list values unchanged."""
        data = [1, 2, 3, "four"]
        result = ensure_list(data)
        assert result == data
        assert result is data

    def test_works_with_empty_list(self) -> None:
        """Test ensure_list with empty list."""
        result = ensure_list([])
        assert result == []

    def test_raises_typeerror_for_non_list(self) -> None:
        """Test that ensure_list raises TypeError for non-list values."""
        with pytest.raises(TypeError, match="Expected 'value' to be list, got dict"):
            ensure_list({"a": 1})

        with pytest.raises(TypeError, match="Expected 'value' to be list, got tuple"):
            ensure_list((1, 2, 3))

        with pytest.raises(TypeError, match="Expected 'value' to be list, got str"):
            ensure_list("not a list")

    def test_custom_name_in_error_message(self) -> None:
        """Test ensure_list uses custom name in error message."""
        with pytest.raises(TypeError, match="Expected 'items' to be list, got set"):
            ensure_list({1, 2, 3}, name="items")
