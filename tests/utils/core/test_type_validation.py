"""Production tests for utils/core/type_validation.py.

This module validates runtime type validation utilities critical for secure
binary analysis and license validation operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.core.type_validation import (
    create_error_result,
    validate_bytes_data,
    validate_file_path,
    validate_integer_range,
    validate_memory_address,
    validate_process_id,
    validate_string_list,
)


class TestValidateFilePath:
    """Test validate_file_path for path validation."""

    def test_valid_file_path(self) -> None:
        """validate_file_path accepts valid existing file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            validate_file_path(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejects_non_string_path(self) -> None:
        """validate_file_path rejects non-string path types."""
        with pytest.raises(TypeError, match="path must be str, bytes, or PathLike"):
            validate_file_path(123)  # type: ignore[arg-type]

    def test_rejects_empty_path(self) -> None:
        """validate_file_path rejects empty paths by default."""
        with pytest.raises(ValueError, match="path cannot be empty"):
            validate_file_path("")

    def test_accepts_empty_path_when_allowed(self) -> None:
        """validate_file_path accepts empty paths when allow_empty=True."""
        validate_file_path("", check_exists=False, allow_empty=True)

    def test_rejects_whitespace_only_path(self) -> None:
        """validate_file_path rejects whitespace-only paths."""
        with pytest.raises(ValueError, match="path cannot be empty"):
            validate_file_path("   ")

    def test_checks_file_existence(self) -> None:
        """validate_file_path validates file existence when check_exists=True."""
        with pytest.raises(ValueError, match="Path is not a file"):
            validate_file_path("D:/nonexistent/file.exe")

    def test_skips_existence_check_when_disabled(self) -> None:
        """validate_file_path skips existence check when check_exists=False."""
        validate_file_path("D:/nonexistent.exe", check_exists=False)

    def test_checks_read_permission(self) -> None:
        """validate_file_path validates read permissions."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            validate_file_path(temp_path, check_readable=True)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_accepts_pathlib_path(self) -> None:
        """validate_file_path accepts pathlib.Path objects."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            validate_file_path(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_accepts_bytes_path(self) -> None:
        """validate_file_path accepts bytes paths."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name.encode()

        try:
            validate_file_path(temp_path)
        finally:
            Path(temp_path.decode()).unlink(missing_ok=True)


class TestValidateIntegerRange:
    """Test validate_integer_range for integer validation."""

    def test_valid_integer(self) -> None:
        """validate_integer_range accepts valid integers."""
        validate_integer_range(42, "test_param")
        validate_integer_range(0, "zero_value")
        validate_integer_range(-10, "negative_value")

    def test_rejects_non_integer(self) -> None:
        """validate_integer_range rejects non-integer types."""
        with pytest.raises(TypeError, match="must be int"):
            validate_integer_range(3.14, "param")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="must be int"):
            validate_integer_range("123", "param")  # type: ignore[arg-type]

    def test_rejects_negative_when_disallowed(self) -> None:
        """validate_integer_range rejects negative values when allow_negative=False."""
        with pytest.raises(ValueError, match="cannot be negative"):
            validate_integer_range(-5, "param", allow_negative=False)

    def test_accepts_negative_when_allowed(self) -> None:
        """validate_integer_range accepts negative values when allow_negative=True."""
        validate_integer_range(-100, "param", allow_negative=True)

    def test_validates_minimum_value(self) -> None:
        """validate_integer_range enforces minimum value constraint."""
        with pytest.raises(ValueError, match="must be >= 10"):
            validate_integer_range(5, "param", min_value=10)

    def test_accepts_exact_minimum(self) -> None:
        """validate_integer_range accepts value equal to minimum."""
        validate_integer_range(10, "param", min_value=10)

    def test_validates_maximum_value(self) -> None:
        """validate_integer_range enforces maximum value constraint."""
        with pytest.raises(ValueError, match="must be <= 100"):
            validate_integer_range(150, "param", max_value=100)

    def test_accepts_exact_maximum(self) -> None:
        """validate_integer_range accepts value equal to maximum."""
        validate_integer_range(100, "param", max_value=100)

    def test_validates_range_bounds(self) -> None:
        """validate_integer_range enforces both min and max constraints."""
        validate_integer_range(50, "param", min_value=0, max_value=100)

        with pytest.raises(ValueError, match="must be >= 0"):
            validate_integer_range(-1, "param", min_value=0, max_value=100)

        with pytest.raises(ValueError, match="must be <= 100"):
            validate_integer_range(101, "param", min_value=0, max_value=100)


class TestValidateBytesData:
    """Test validate_bytes_data for binary data validation."""

    def test_valid_bytes(self) -> None:
        """validate_bytes_data accepts valid bytes objects."""
        validate_bytes_data(b"test data")
        validate_bytes_data(b"\x90\x50\x56\x53")

    def test_rejects_non_bytes(self) -> None:
        """validate_bytes_data rejects non-bytes types."""
        with pytest.raises(TypeError, match="must be bytes"):
            validate_bytes_data("string")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="must be bytes"):
            validate_bytes_data([1, 2, 3])  # type: ignore[arg-type]

    def test_rejects_empty_by_default(self) -> None:
        """validate_bytes_data rejects empty bytes by default."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_bytes_data(b"", allow_empty=False)

    def test_accepts_empty_when_allowed(self) -> None:
        """validate_bytes_data accepts empty bytes when allow_empty=True."""
        validate_bytes_data(b"", allow_empty=True)

    def test_validates_minimum_size(self) -> None:
        """validate_bytes_data enforces minimum size constraint."""
        with pytest.raises(ValueError, match="must be at least 10 bytes"):
            validate_bytes_data(b"short", min_size=10)

    def test_accepts_exact_minimum_size(self) -> None:
        """validate_bytes_data accepts data equal to minimum size."""
        validate_bytes_data(b"1234567890", min_size=10)

    def test_validates_maximum_size(self) -> None:
        """validate_bytes_data enforces maximum size constraint."""
        large_data = b"A" * 1000
        with pytest.raises(ValueError, match="too large"):
            validate_bytes_data(large_data, max_size=100)

    def test_accepts_exact_maximum_size(self) -> None:
        """validate_bytes_data accepts data equal to maximum size."""
        data = b"A" * 100
        validate_bytes_data(data, max_size=100)

    def test_validates_size_range(self) -> None:
        """validate_bytes_data enforces both min and max size constraints."""
        validate_bytes_data(b"valid data", min_size=5, max_size=20)

        with pytest.raises(ValueError, match="must be at least"):
            validate_bytes_data(b"bad", min_size=5, max_size=20)

        with pytest.raises(ValueError, match="too large"):
            validate_bytes_data(b"A" * 30, min_size=5, max_size=20)

    def test_custom_parameter_name(self) -> None:
        """validate_bytes_data uses custom parameter name in errors."""
        with pytest.raises(TypeError, match="binary_data must be bytes"):
            validate_bytes_data("invalid", name="binary_data")  # type: ignore[arg-type]


class TestValidateStringList:
    """Test validate_string_list for list validation."""

    def test_valid_string_list(self) -> None:
        """validate_string_list accepts valid string lists."""
        validate_string_list(["item1", "item2", "item3"])

    def test_rejects_non_list(self) -> None:
        """validate_string_list rejects non-list types."""
        with pytest.raises(TypeError, match="must be list"):
            validate_string_list("not a list")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="must be list"):
            validate_string_list(("tuple", "not", "list"))  # type: ignore[arg-type]

    def test_rejects_empty_list_by_default(self) -> None:
        """validate_string_list rejects empty lists by default."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_string_list([], allow_empty_list=False)

    def test_accepts_empty_list_when_allowed(self) -> None:
        """validate_string_list accepts empty lists when allow_empty_list=True."""
        validate_string_list([], allow_empty_list=True)

    def test_rejects_non_string_items(self) -> None:
        """validate_string_list rejects lists containing non-strings."""
        with pytest.raises(TypeError, match=r"strings\[1\] must be str"):
            validate_string_list(["valid", 123, "string"])  # type: ignore[list-item]

    def test_rejects_empty_strings_by_default(self) -> None:
        """validate_string_list rejects empty strings in list by default."""
        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            validate_string_list(["valid", "", "string"], allow_empty_strings=False)

    def test_accepts_empty_strings_when_allowed(self) -> None:
        """validate_string_list accepts empty strings when allow_empty_strings=True."""
        validate_string_list(["valid", "", "string"], allow_empty_strings=True)

    def test_rejects_whitespace_only_strings(self) -> None:
        """validate_string_list rejects whitespace-only strings."""
        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            validate_string_list(["valid", "   ", "string"])

    def test_validates_maximum_length(self) -> None:
        """validate_string_list enforces maximum list length."""
        with pytest.raises(ValueError, match="too long"):
            validate_string_list(["a", "b", "c", "d", "e"], max_length=3)

    def test_accepts_exact_maximum_length(self) -> None:
        """validate_string_list accepts lists equal to maximum length."""
        validate_string_list(["a", "b", "c"], max_length=3)


class TestValidateMemoryAddress:
    """Test validate_memory_address for address validation."""

    def test_valid_memory_address(self) -> None:
        """validate_memory_address accepts valid memory addresses."""
        validate_memory_address(0x400000)
        validate_memory_address(0x7FFFFFFF)

    def test_rejects_non_integer(self) -> None:
        """validate_memory_address rejects non-integer types."""
        with pytest.raises(TypeError, match="must be int"):
            validate_memory_address("0x400000")  # type: ignore[arg-type]

    def test_rejects_zero_by_default(self) -> None:
        """validate_memory_address rejects zero (null pointer) by default."""
        with pytest.raises(ValueError, match="cannot be zero"):
            validate_memory_address(0)

    def test_accepts_zero_when_allowed(self) -> None:
        """validate_memory_address accepts zero when allow_zero=True."""
        validate_memory_address(0, allow_zero=True)

    def test_rejects_negative_addresses(self) -> None:
        """validate_memory_address rejects negative addresses."""
        with pytest.raises(ValueError, match="cannot be negative"):
            validate_memory_address(-100)

    def test_rejects_too_large_addresses(self) -> None:
        """validate_memory_address rejects addresses beyond 48-bit range."""
        max_valid = (1 << 48) - 1
        validate_memory_address(max_valid)

        with pytest.raises(ValueError, match="too large"):
            validate_memory_address(max_valid + 1)

    def test_realistic_memory_addresses(self) -> None:
        """validate_memory_address accepts realistic memory addresses."""
        validate_memory_address(0x00401000)
        validate_memory_address(0x7FFFFFFFFFFF)


class TestValidateProcessId:
    """Test validate_process_id for PID validation."""

    def test_valid_process_id(self) -> None:
        """validate_process_id accepts valid process IDs."""
        validate_process_id(1234)
        validate_process_id(os.getpid())

    def test_rejects_non_integer(self) -> None:
        """validate_process_id rejects non-integer types."""
        with pytest.raises(TypeError, match="must be int"):
            validate_process_id("1234")  # type: ignore[arg-type]

    def test_rejects_zero(self) -> None:
        """validate_process_id rejects zero as invalid PID."""
        with pytest.raises(ValueError, match="must be positive"):
            validate_process_id(0)

    def test_rejects_negative(self) -> None:
        """validate_process_id rejects negative PIDs."""
        with pytest.raises(ValueError, match="must be positive"):
            validate_process_id(-100)

    def test_rejects_too_large_pid(self) -> None:
        """validate_process_id rejects PIDs beyond system maximum."""
        max_pid = 4194304
        validate_process_id(max_pid)

        with pytest.raises(ValueError, match="too large"):
            validate_process_id(max_pid + 1)

    def test_realistic_process_ids(self) -> None:
        """validate_process_id accepts realistic process IDs."""
        validate_process_id(4)
        validate_process_id(1000)
        validate_process_id(65536)


class TestCreateErrorResult:
    """Test create_error_result for error dictionary creation."""

    def test_creates_basic_error_result(self) -> None:
        """create_error_result creates error dictionary with message."""
        result = create_error_result("Test error message")

        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "Test error message"

    def test_uses_template_when_provided(self) -> None:
        """create_error_result merges error with template."""
        template = {"status": "failed", "data": None, "error": None}
        result = create_error_result("Error occurred", result_template=template)

        assert result["status"] == "failed"
        assert result["data"] is None
        assert result["error"] == "Error occurred"

    def test_overwrites_template_error(self) -> None:
        """create_error_result overwrites template error field."""
        template = {"error": "old error", "value": 42}
        result = create_error_result("new error", result_template=template)

        assert result["error"] == "new error"
        assert result["value"] == 42

    def test_does_not_modify_original_template(self) -> None:
        """create_error_result does not modify original template."""
        template: dict[str, Any] = {"error": None, "data": "test"}
        create_error_result("Error message", result_template=template)

        assert template["error"] is None
        assert template["data"] == "test"

    def test_creates_default_template_when_none(self) -> None:
        """create_error_result creates default template when none provided."""
        result = create_error_result("Error message")

        assert "error" in result
        assert result["error"] == "Error message"


class TestValidationIntegration:
    """Test validation functions in integrated scenarios."""

    def test_validate_binary_analysis_inputs(self) -> None:
        """Validation functions work together for binary analysis inputs."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            binary_path = f.name
            f.write(b"\x90\x50\x56\x53" * 100)

        try:
            validate_file_path(binary_path, check_readable=True)
            validate_bytes_data(b"\x90\x50\x56\x53", min_size=4, max_size=1000000)
            validate_memory_address(0x400000)
        finally:
            Path(binary_path).unlink(missing_ok=True)

    def test_validate_license_processing_inputs(self) -> None:
        """Validation functions work for license processing scenarios."""
        validate_string_list(["ABC-123", "DEF-456"], allow_empty_strings=False)
        validate_bytes_data(b"license_key_hash", min_size=10)
        validate_integer_range(86400, "expiry_seconds", min_value=0)

    def test_validation_error_messages_include_parameter_names(self) -> None:
        """Validation errors include parameter names for debugging."""
        with pytest.raises(TypeError, match="binary_data must be bytes"):
            validate_bytes_data("invalid", name="binary_data")  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="license_keys cannot be empty"):
            validate_string_list([], name="license_keys", allow_empty_list=False)
