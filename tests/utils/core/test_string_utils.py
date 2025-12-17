"""Production tests for utils/core/string_utils.py.

This module validates string formatting and ASCII extraction utilities for
binary analysis and license key processing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.utils.core.string_utils import extract_ascii_strings, format_bytes


class TestFormatBytes:
    """Test format_bytes for human-readable file size formatting."""

    def test_format_bytes_exact_boundaries(self) -> None:
        """format_bytes handles exact unit boundaries correctly."""
        assert format_bytes(1) == "1 B"
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1024 * 1024) == "1.00 MB"
        assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"

    def test_format_bytes_below_kilobyte(self) -> None:
        """format_bytes displays bytes without decimals for values under 1KB."""
        assert format_bytes(0) == "0 B"
        assert format_bytes(512) == "512 B"
        assert format_bytes(1023) == "1023 B"

    def test_format_kilobytes(self) -> None:
        """format_bytes displays kilobytes with 2 decimal places."""
        assert format_bytes(1536) == "1.50 KB"
        assert format_bytes(2048) == "2.00 KB"
        assert format_bytes(10240) == "10.00 KB"

    def test_format_megabytes(self) -> None:
        """format_bytes displays megabytes with 2 decimal places."""
        assert format_bytes(1572864) == "1.50 MB"
        assert format_bytes(5242880) == "5.00 MB"
        assert format_bytes(52428800) == "50.00 MB"

    def test_format_gigabytes(self) -> None:
        """format_bytes displays gigabytes with 2 decimal places."""
        assert format_bytes(1610612736) == "1.50 GB"
        assert format_bytes(2147483648) == "2.00 GB"
        assert format_bytes(10737418240) == "10.00 GB"

    def test_format_bytes_realistic_file_sizes(self) -> None:
        """format_bytes handles realistic binary file sizes."""
        assert "KB" in format_bytes(50 * 1024)
        assert "MB" in format_bytes(100 * 1024 * 1024)
        assert "GB" in format_bytes(2 * 1024 * 1024 * 1024)

    @pytest.mark.parametrize(
        "size,expected_unit",
        [
            (500, "B"),
            (2000, "KB"),
            (2000000, "MB"),
            (2000000000, "GB"),
        ],
    )
    def test_format_bytes_unit_selection(self, size: int, expected_unit: str) -> None:
        """format_bytes selects appropriate unit for given sizes."""
        result = format_bytes(size)
        assert expected_unit in result

    def test_format_bytes_precision(self) -> None:
        """format_bytes maintains 2 decimal precision for KB/MB/GB."""
        assert format_bytes(1536) == "1.50 KB"
        assert format_bytes(1234567) == "1.18 MB"
        assert format_bytes(1234567890) == "1.15 GB"

    def test_format_bytes_large_values(self) -> None:
        """format_bytes handles very large file sizes."""
        size_100gb = 100 * 1024 * 1024 * 1024
        result = format_bytes(size_100gb)
        assert "GB" in result
        assert "100.00" in result


class TestExtractAsciiStrings:
    """Test extract_ascii_strings for binary string extraction."""

    def test_extract_simple_string(self) -> None:
        """extract_ascii_strings extracts simple ASCII strings from binary data."""
        data = b"Hello World\x00\x90\x50"
        result = extract_ascii_strings(data)

        assert "Hello World" in result

    def test_extract_multiple_strings(self) -> None:
        """extract_ascii_strings extracts multiple strings from binary."""
        data = b"License\x00\x00Serial\x00\x00Key123"
        result = extract_ascii_strings(data)

        assert "License" in result
        assert "Serial" in result
        assert "Key123" in result

    def test_extract_minimum_length_default(self) -> None:
        """extract_ascii_strings uses minimum length of 4 by default."""
        data = b"OK\x00Test\x00Valid"
        result = extract_ascii_strings(data)

        assert "OK" not in result
        assert "Test" in result
        assert "Valid" in result

    def test_extract_custom_minimum_length(self) -> None:
        """extract_ascii_strings respects custom minimum length."""
        data = b"AB\x00\x00ABCD\x00\x00ABCDEFGH"
        result = extract_ascii_strings(data, min_length=2)

        assert "AB" in result
        assert "ABCD" in result
        assert "ABCDEFGH" in result

    def test_extract_from_pe_header_like_data(self) -> None:
        """extract_ascii_strings extracts strings from PE-like binary data."""
        data = b"MZ\x90\x00This program cannot be run in DOS mode\x00\x00PE\x00\x00"
        result = extract_ascii_strings(data, min_length=10)

        assert any("program" in s for s in result)

    def test_extract_license_keys(self) -> None:
        """extract_ascii_strings finds license key patterns in binary."""
        data = b"\x90\x50\x56ABC-DEF-GHI-JKL\x00\x00Serial:12345\x00"
        result = extract_ascii_strings(data)

        assert "ABC-DEF-GHI-JKL" in result
        assert "Serial:12345" in result

    def test_extract_urls_and_domains(self) -> None:
        """extract_ascii_strings extracts URLs and domain names."""
        data = b"\x00\x00https://license.example.com/validate\x00\x00api.server.com\x00"
        result = extract_ascii_strings(data)

        assert "https://license.example.com/validate" in result
        assert "api.server.com" in result

    def test_extract_ignores_non_printable(self) -> None:
        """extract_ascii_strings ignores non-printable characters."""
        data = b"Valid\x01\x02\x03String"
        result = extract_ascii_strings(data)

        assert "Valid" in result
        assert "String" in result
        assert len(result) == 2

    def test_extract_handles_empty_data(self) -> None:
        """extract_ascii_strings handles empty binary data."""
        result = extract_ascii_strings(b"")
        assert result == []

    def test_extract_handles_no_strings(self) -> None:
        """extract_ascii_strings handles data with no valid strings."""
        data = b"\x00\x01\x02\x03\x90\x50\x56\x53"
        result = extract_ascii_strings(data)
        assert result == []

    def test_extract_printable_ascii_range(self) -> None:
        """extract_ascii_strings only accepts printable ASCII (32-126)."""
        data = b"Test\x1fString\x7fEnd"
        result = extract_ascii_strings(data)

        assert "Test" in result
        assert "String" in result

    def test_extract_with_spaces_and_punctuation(self) -> None:
        """extract_ascii_strings preserves spaces and punctuation."""
        data = b"Hello, World!\x00License Key: ABC-123\x00"
        result = extract_ascii_strings(data)

        assert "Hello, World!" in result
        assert "License Key: ABC-123" in result

    def test_extract_final_string_without_terminator(self) -> None:
        """extract_ascii_strings extracts final string even without null terminator."""
        data = b"\x00\x00FinalString"
        result = extract_ascii_strings(data)

        assert "FinalString" in result

    def test_extract_from_real_binary_pattern(self) -> None:
        """extract_ascii_strings finds strings in realistic binary patterns."""
        data = (
            b"\x90\x50\x56\x53\x48"
            b"VMProtect\x00"
            b"\x00\x00\x00\x00"
            b"License Server\x00"
            b"\x90\x90\x90"
        )
        result = extract_ascii_strings(data)

        assert "VMProtect" in result
        assert "License Server" in result

    @pytest.mark.parametrize(
        "data,min_len,expected_count",
        [
            (b"ABCD\x00EFGH\x00IJ", 4, 2),
            (b"ABC\x00DEFG\x00HIJK", 4, 2),
            (b"Short\x00VeryLongString\x00OK", 10, 1),
        ],
    )
    def test_extract_with_various_lengths(
        self,
        data: bytes,
        min_len: int,
        expected_count: int,
    ) -> None:
        """extract_ascii_strings correctly filters by minimum length."""
        result = extract_ascii_strings(data, min_length=min_len)
        assert len(result) == expected_count

    def test_extract_handles_bytearray(self) -> None:
        """extract_ascii_strings works with bytearray input."""
        data = bytearray(b"Test String\x00\x90\x50")
        result = extract_ascii_strings(data)

        assert "Test String" in result

    def test_extract_preserves_order(self) -> None:
        """extract_ascii_strings preserves string order from binary."""
        data = b"First\x00\x00Second\x00\x00Third"
        result = extract_ascii_strings(data)

        assert result == ["First", "Second", "Third"]

    def test_extract_license_validation_strings(self) -> None:
        """extract_ascii_strings finds license validation related strings."""
        data = (
            b"\x00\x00CheckLicense\x00ValidateSerial\x00"
            b"ActivationCode\x00TrialExpired\x00"
        )
        result = extract_ascii_strings(data)

        assert "CheckLicense" in result
        assert "ValidateSerial" in result
        assert "ActivationCode" in result
        assert "TrialExpired" in result

    def test_extract_from_encrypted_section_boundaries(self) -> None:
        """extract_ascii_strings finds strings at encrypted section boundaries."""
        data = (
            b"\xff\xfe\xfd\xfc"
            b"Unprotected\x00"
            b"\x90\x90\x90\x90"
            b"ClearText"
            b"\xff\xfe\xfd"
        )
        result = extract_ascii_strings(data)

        assert "Unprotected" in result
        assert "ClearText" in result
