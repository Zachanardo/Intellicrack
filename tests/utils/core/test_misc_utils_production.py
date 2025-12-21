"""Production tests for misc_utils.py module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

Tests validate utility functions for path handling, formatting, and validation
used throughout binary analysis and protection cracking operations.
"""

import tempfile
from pathlib import Path

import pytest


def test_misc_utils_log_message_includes_timestamp() -> None:
    """log_message returns message with timestamp prefix."""
    from intellicrack.utils.core.misc_utils import log_message

    msg = "Test message"
    result = log_message(msg)

    assert msg in result
    assert result.startswith("[")
    assert "]" in result
    assert len(result) > len(msg)


def test_misc_utils_log_message_timestamp_format_is_consistent() -> None:
    """log_message uses consistent YYYY-MM-DD HH:MM:SS timestamp format."""
    import re

    from intellicrack.utils.core.misc_utils import log_message

    result = log_message("test")

    timestamp_pattern = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
    assert re.search(timestamp_pattern, result)


def test_misc_utils_get_timestamp_default_format() -> None:
    """get_timestamp returns formatted timestamp with default format."""
    import re

    from intellicrack.utils.core.misc_utils import get_timestamp

    result = get_timestamp()

    timestamp_pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
    assert re.match(timestamp_pattern, result)


def test_misc_utils_get_timestamp_custom_format() -> None:
    """get_timestamp returns timestamp in custom format."""
    from intellicrack.utils.core.misc_utils import get_timestamp

    custom_format = "%Y%m%d_%H%M%S"
    result = get_timestamp(custom_format)

    assert len(result) == 15
    assert result.isdigit() or "_" in result


def test_misc_utils_format_bytes_handles_small_sizes() -> None:
    """format_bytes correctly formats byte sizes."""
    from intellicrack.utils.core.misc_utils import format_bytes

    assert format_bytes(0) == "0.00 B"
    assert format_bytes(512) == "512.00 B"
    assert format_bytes(1023) == "1023.00 B"


def test_misc_utils_format_bytes_handles_kilobytes() -> None:
    """format_bytes correctly formats kilobyte sizes."""
    from intellicrack.utils.core.misc_utils import format_bytes

    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(1536) == "1.50 KB"
    assert format_bytes(2048) == "2.00 KB"


def test_misc_utils_format_bytes_handles_megabytes() -> None:
    """format_bytes correctly formats megabyte sizes."""
    from intellicrack.utils.core.misc_utils import format_bytes

    assert format_bytes(1024 * 1024) == "1.00 MB"
    assert format_bytes(5 * 1024 * 1024) == "5.00 MB"


def test_misc_utils_format_bytes_handles_gigabytes() -> None:
    """format_bytes correctly formats gigabyte sizes."""
    from intellicrack.utils.core.misc_utils import format_bytes

    assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"
    assert format_bytes(3 * 1024 * 1024 * 1024) == "3.00 GB"


def test_misc_utils_format_bytes_custom_precision() -> None:
    """format_bytes respects custom precision parameter."""
    from intellicrack.utils.core.misc_utils import format_bytes

    size = 1536
    assert format_bytes(size, precision=0) == "2 KB"
    assert format_bytes(size, precision=2) == "1.50 KB"
    assert format_bytes(size, precision=4) == "1.5000 KB"


def test_misc_utils_validate_path_rejects_relative_paths() -> None:
    """validate_path rejects relative paths for security."""
    from intellicrack.utils.core.misc_utils import validate_path

    relative_path = "relative/path/file.exe"
    assert not validate_path(relative_path)


def test_misc_utils_validate_path_accepts_absolute_existing_paths() -> None:
    """validate_path accepts absolute paths that exist."""
    from intellicrack.utils.core.misc_utils import validate_path

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            assert validate_path(str(tmp_path), must_exist=True)
        finally:
            tmp_path.unlink()


def test_misc_utils_validate_path_accepts_nonexistent_when_allowed() -> None:
    """validate_path accepts non-existent absolute paths when must_exist=False."""
    from intellicrack.utils.core.misc_utils import validate_path

    with tempfile.TemporaryDirectory() as tmpdir:
        nonexistent = Path(tmpdir) / "nonexistent.bin"
        assert validate_path(str(nonexistent), must_exist=False)


def test_misc_utils_validate_path_rejects_nonexistent_when_required() -> None:
    """validate_path rejects non-existent paths when must_exist=True."""
    from intellicrack.utils.core.misc_utils import validate_path

    with tempfile.TemporaryDirectory() as tmpdir:
        nonexistent = Path(tmpdir) / "nonexistent.bin"
        assert not validate_path(str(nonexistent), must_exist=True)


def test_misc_utils_sanitize_filename_removes_invalid_characters() -> None:
    """sanitize_filename removes Windows-invalid characters."""
    from intellicrack.utils.core.misc_utils import sanitize_filename

    invalid = 'test<>:"/\\|?*.exe'
    result = sanitize_filename(invalid)

    assert "<" not in result
    assert ">" not in result
    assert ":" not in result
    assert '"' not in result
    assert "/" not in result
    assert "\\" not in result
    assert "|" not in result
    assert "?" not in result
    assert "*" not in result


def test_misc_utils_sanitize_filename_preserves_valid_characters() -> None:
    """sanitize_filename preserves valid filename characters."""
    from intellicrack.utils.core.misc_utils import sanitize_filename

    valid = "valid_filename-123.exe"
    result = sanitize_filename(valid)

    assert result == valid


def test_misc_utils_sanitize_filename_custom_replacement() -> None:
    """sanitize_filename uses custom replacement character."""
    from intellicrack.utils.core.misc_utils import sanitize_filename

    invalid = "test:file.exe"
    result = sanitize_filename(invalid, replacement="-")

    assert ":" not in result
    assert "-" in result


def test_misc_utils_sanitize_filename_handles_edge_cases() -> None:
    """sanitize_filename handles edge cases like empty strings."""
    from intellicrack.utils.core.misc_utils import sanitize_filename

    assert sanitize_filename("") == "unnamed"
    assert sanitize_filename("   ") == "unnamed"
    assert sanitize_filename("...") == "unnamed"


def test_misc_utils_truncate_string_preserves_short_strings() -> None:
    """truncate_string preserves strings shorter than max_length."""
    from intellicrack.utils.core.misc_utils import truncate_string

    short = "short string"
    result = truncate_string(short, max_length=100)

    assert result == short


def test_misc_utils_truncate_string_truncates_long_strings() -> None:
    """truncate_string truncates strings longer than max_length."""
    from intellicrack.utils.core.misc_utils import truncate_string

    long_string = "a" * 200
    result = truncate_string(long_string, max_length=50)

    assert len(result) == 50
    assert result.endswith("...")


def test_misc_utils_truncate_string_custom_suffix() -> None:
    """truncate_string uses custom suffix for truncated strings."""
    from intellicrack.utils.core.misc_utils import truncate_string

    long_string = "a" * 200
    result = truncate_string(long_string, max_length=20, suffix="[cut]")

    assert result.endswith("[cut]")
    assert len(result) == 20


def test_misc_utils_safe_str_converts_objects_to_string() -> None:
    """safe_str safely converts various objects to strings."""
    from intellicrack.utils.core.misc_utils import safe_str

    assert safe_str(123) == "123"
    assert safe_str(3.14) == "3.14"
    assert safe_str([1, 2, 3]) == "[1, 2, 3]"
    assert safe_str({"key": "value"})


def test_misc_utils_safe_str_truncates_long_representations() -> None:
    """safe_str truncates long object representations."""
    from intellicrack.utils.core.misc_utils import safe_str

    long_list = list(range(1000))
    result = safe_str(long_list, max_length=50)

    assert len(result) <= 50


def test_misc_utils_parse_size_string_handles_bytes() -> None:
    """parse_size_string correctly parses byte sizes."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    assert parse_size_string("100") == 100
    assert parse_size_string("100B") == 100
    assert parse_size_string("100 B") == 100


def test_misc_utils_parse_size_string_handles_kilobytes() -> None:
    """parse_size_string correctly parses kilobyte sizes."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    assert parse_size_string("1KB") == 1024
    assert parse_size_string("2.5KB") == int(2.5 * 1024)


def test_misc_utils_parse_size_string_handles_megabytes() -> None:
    """parse_size_string correctly parses megabyte sizes."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    assert parse_size_string("1MB") == 1024**2
    assert parse_size_string("10 MB") == 10 * 1024**2


def test_misc_utils_parse_size_string_handles_gigabytes() -> None:
    """parse_size_string correctly parses gigabyte sizes."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    assert parse_size_string("1GB") == 1024**3
    assert parse_size_string("5GB") == 5 * 1024**3


def test_misc_utils_parse_size_string_case_insensitive() -> None:
    """parse_size_string handles case-insensitive unit specifications."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    assert parse_size_string("1kb") == 1024
    assert parse_size_string("1KB") == 1024
    assert parse_size_string("1Kb") == 1024


def test_misc_utils_parse_size_string_raises_on_invalid_input() -> None:
    """parse_size_string raises ValueError for invalid input."""
    from intellicrack.utils.core.misc_utils import parse_size_string

    with pytest.raises(ValueError):
        parse_size_string("invalid")

    with pytest.raises(ValueError):
        parse_size_string("10XB")


def test_misc_utils_get_file_extension_returns_extension_with_dot() -> None:
    """get_file_extension returns file extension including dot."""
    from intellicrack.utils.core.misc_utils import get_file_extension

    assert get_file_extension("test.exe") == ".exe"
    assert get_file_extension("archive.tar.gz") == ".gz"
    assert get_file_extension("noext") == ""


def test_misc_utils_get_file_extension_lowercase_option() -> None:
    """get_file_extension converts extension to lowercase when requested."""
    from intellicrack.utils.core.misc_utils import get_file_extension

    assert get_file_extension("TEST.EXE", lower=True) == ".exe"
    assert get_file_extension("TEST.EXE", lower=False) == ".EXE"


def test_misc_utils_ensure_directory_exists_creates_directory() -> None:
    """ensure_directory_exists creates directory if it doesn't exist."""
    from intellicrack.utils.core.misc_utils import ensure_directory_exists

    with tempfile.TemporaryDirectory() as tmpdir:
        new_dir = Path(tmpdir) / "new_directory"
        assert not new_dir.exists()

        result = ensure_directory_exists(new_dir)

        assert result is True
        assert new_dir.exists()
        assert new_dir.is_dir()


def test_misc_utils_ensure_directory_exists_handles_existing_directory() -> None:
    """ensure_directory_exists succeeds when directory already exists."""
    from intellicrack.utils.core.misc_utils import ensure_directory_exists

    with tempfile.TemporaryDirectory() as tmpdir:
        result = ensure_directory_exists(tmpdir)
        assert result is True


def test_misc_utils_ensure_directory_exists_creates_nested_directories() -> None:
    """ensure_directory_exists creates nested directory structure."""
    from intellicrack.utils.core.misc_utils import ensure_directory_exists

    with tempfile.TemporaryDirectory() as tmpdir:
        nested = Path(tmpdir) / "level1" / "level2" / "level3"
        result = ensure_directory_exists(nested)

        assert result is True
        assert nested.exists()


def test_misc_utils_is_valid_ip_address_validates_ipv4() -> None:
    """is_valid_ip_address correctly validates IPv4 addresses."""
    from intellicrack.utils.core.misc_utils import is_valid_ip_address

    assert is_valid_ip_address("192.168.1.1")
    assert is_valid_ip_address("127.0.0.1")
    assert is_valid_ip_address("8.8.8.8")
    assert is_valid_ip_address("255.255.255.255")
    assert is_valid_ip_address("0.0.0.0")


def test_misc_utils_is_valid_ip_address_rejects_invalid_ipv4() -> None:
    """is_valid_ip_address rejects invalid IPv4 addresses."""
    from intellicrack.utils.core.misc_utils import is_valid_ip_address

    assert not is_valid_ip_address("256.1.1.1")
    assert not is_valid_ip_address("192.168.1")
    assert not is_valid_ip_address("192.168.1.1.1")
    assert not is_valid_ip_address("abc.def.ghi.jkl")


def test_misc_utils_is_valid_ip_address_validates_ipv6() -> None:
    """is_valid_ip_address correctly validates IPv6 addresses."""
    from intellicrack.utils.core.misc_utils import is_valid_ip_address

    assert is_valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert is_valid_ip_address("::1")
    assert is_valid_ip_address("fe80::1")


def test_misc_utils_is_valid_port_validates_valid_ports() -> None:
    """is_valid_port correctly validates port numbers."""
    from intellicrack.utils.core.misc_utils import is_valid_port

    assert is_valid_port(80)
    assert is_valid_port(443)
    assert is_valid_port(8080)
    assert is_valid_port(1)
    assert is_valid_port(65535)
    assert is_valid_port("8080")


def test_misc_utils_is_valid_port_rejects_invalid_ports() -> None:
    """is_valid_port rejects invalid port numbers."""
    from intellicrack.utils.core.misc_utils import is_valid_port

    assert not is_valid_port(0)
    assert not is_valid_port(65536)
    assert not is_valid_port(-1)
    assert not is_valid_port("invalid")


def test_misc_utils_all_exports_accessible() -> None:
    """All exported functions are accessible from misc_utils module."""
    from intellicrack.utils.core import misc_utils

    for name in misc_utils.__all__:
        assert hasattr(misc_utils, name), f"Exported function {name} not accessible"
