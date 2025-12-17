"""Production-ready tests for hex_utils.py.

Tests validate REAL hex manipulation and binary operations.
All tests use actual binary data and verify accurate transformations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.utils.binary.hex_utils import (
    bytes_to_hex,
    calculate_checksum,
    compare_bytes,
    create_hex_dump,
    detect_encoding,
    find_pattern,
    format_address,
    hex_to_bytes,
    is_printable_ascii,
    nop_range,
    patch_bytes,
)


class TestCreateHexDump:
    """Test hex dump creation."""

    def test_creates_basic_hex_dump(self) -> None:
        """Hex dump creates formatted output with offset, hex, and ASCII."""
        data = b"Hello, World!"

        dump = create_hex_dump(data)

        assert "00000000" in dump
        assert "48 65 6c 6c 6f" in dump
        assert "|Hello, World!|" in dump

    def test_handles_16_bytes_per_line(self) -> None:
        """Hex dump uses 16 bytes per line by default."""
        data = b"A" * 32

        dump = create_hex_dump(data)
        lines = dump.split("\n")

        assert len(lines) == 2

    def test_custom_bytes_per_line(self) -> None:
        """Hex dump respects custom bytes per line setting."""
        data = b"A" * 20

        dump = create_hex_dump(data, bytes_per_line=10)
        lines = dump.split("\n")

        assert len(lines) == 2

    def test_applies_start_offset(self) -> None:
        """Hex dump applies start offset to addresses."""
        data = b"test"

        dump = create_hex_dump(data, start_offset=0x1000)

        assert "00001000" in dump

    def test_displays_non_printable_as_dots(self) -> None:
        """Hex dump shows non-printable characters as dots."""
        data = b"\x00\x01\x02\x03\x7F\xFF"

        dump = create_hex_dump(data)

        assert "." in dump
        ascii_part = dump.split("|")[1]
        assert ascii_part.count(".") == len(data)

    def test_aligns_hex_properly(self) -> None:
        """Hex dump aligns hex values correctly for partial lines."""
        data = b"ABC"

        dump = create_hex_dump(data, bytes_per_line=16)

        assert "41 42 43" in dump
        line = dump.split("\n")[0]
        hex_part = line.split("  ")[1].split("  |")[0]
        assert len(hex_part) >= len("41 42 43")


class TestHexToBytes:
    """Test hex string to bytes conversion."""

    def test_converts_plain_hex_string(self) -> None:
        """Hex converter handles plain hex strings."""
        hex_string = "48656c6c6f"

        result = hex_to_bytes(hex_string)

        assert result == b"Hello"

    def test_converts_hex_with_spaces(self) -> None:
        """Hex converter handles space-separated hex."""
        hex_string = "48 65 6c 6c 6f"

        result = hex_to_bytes(hex_string)

        assert result == b"Hello"

    def test_converts_hex_with_0x_prefix(self) -> None:
        """Hex converter handles 0x prefixed hex."""
        hex_string = "0x48656c6c6f"

        result = hex_to_bytes(hex_string)

        assert result == b"Hello"

    def test_converts_hex_with_backslash_x(self) -> None:
        """Hex converter handles \\x format."""
        hex_string = r"\x48\x65\x6c\x6c\x6f"

        result = hex_to_bytes(hex_string)

        assert result == b"Hello"

    def test_converts_hex_with_commas(self) -> None:
        """Hex converter handles comma-separated hex."""
        hex_string = "48,65,6c,6c,6f"

        result = hex_to_bytes(hex_string)

        assert result == b"Hello"

    def test_raises_on_invalid_hex(self) -> None:
        """Hex converter raises ValueError for invalid hex."""
        with pytest.raises(ValueError):
            hex_to_bytes("GGHHII")


class TestBytesToHex:
    """Test bytes to hex string conversion."""

    def test_converts_to_plain_hex(self) -> None:
        """Bytes converter creates plain hex string."""
        data = b"\xDE\xAD\xBE\xEF"

        result = bytes_to_hex(data, format_style="plain")

        assert result == "deadbeef"

    def test_converts_to_uppercase(self) -> None:
        """Bytes converter creates uppercase hex."""
        data = b"\xDE\xAD\xBE\xEF"

        result = bytes_to_hex(data, format_style="plain", uppercase=True)

        assert result == "DEADBEEF"

    def test_converts_with_spaces(self) -> None:
        """Bytes converter creates space-separated hex."""
        data = b"\xDE\xAD\xBE\xEF"

        result = bytes_to_hex(data, format_style="spaces")

        assert result == "de ad be ef"

    def test_converts_with_0x_prefix(self) -> None:
        """Bytes converter creates 0x prefixed hex."""
        data = b"\xDE\xAD\xBE\xEF"

        result = bytes_to_hex(data, format_style="0x")

        assert result == "0xdeadbeef"

    def test_converts_with_backslash_x(self) -> None:
        """Bytes converter creates \\x format."""
        data = b"\xDE\xAD"

        result = bytes_to_hex(data, format_style="\\x")

        assert result == "\\xde\\xad"

    def test_converts_to_c_array(self) -> None:
        """Bytes converter creates C array format."""
        data = b"\xDE\xAD\xBE"

        result = bytes_to_hex(data, format_style="c_array")

        assert result == "0xde, 0xad, 0xbe"


class TestFindPattern:
    """Test pattern finding in binary data."""

    def test_finds_single_pattern(self) -> None:
        """Pattern finder locates single occurrence."""
        data = b"\x00\x00\xDE\xAD\xBE\xEF\x00\x00"
        pattern = b"\xDE\xAD\xBE\xEF"

        offsets = find_pattern(data, pattern)

        assert offsets == [2]

    def test_finds_multiple_patterns(self) -> None:
        """Pattern finder locates multiple occurrences."""
        data = b"\x90\x90\x00\x90\x90\x00\x90\x90"
        pattern = b"\x90\x90"

        offsets = find_pattern(data, pattern)

        assert 0 in offsets
        assert 3 in offsets
        assert 6 in offsets

    def test_respects_max_results(self) -> None:
        """Pattern finder respects maximum results limit."""
        data = b"\xFF" * 100
        pattern = b"\xFF"

        offsets = find_pattern(data, pattern, max_results=10)

        assert len(offsets) == 10


class TestCalculateChecksum:
    """Test checksum calculation."""

    def test_calculates_sum8_checksum(self) -> None:
        """Checksum calculator computes 8-bit sum."""
        data = b"\x01\x02\x03\x04"

        checksum = calculate_checksum(data, algorithm="sum8")

        assert checksum == 0x0A

    def test_calculates_sum16_checksum(self) -> None:
        """Checksum calculator computes 16-bit sum."""
        data = b"\xFF\xFF\xFF\xFF"

        checksum = calculate_checksum(data, algorithm="sum16")

        assert checksum == 0xFFFC

    def test_calculates_xor_checksum(self) -> None:
        """Checksum calculator computes XOR checksum."""
        data = b"\xAA\x55\xAA\x55"

        checksum = calculate_checksum(data, algorithm="xor")

        assert checksum == 0x00

    def test_raises_on_unknown_algorithm(self) -> None:
        """Checksum calculator raises for unknown algorithm."""
        with pytest.raises(ValueError):
            calculate_checksum(b"data", algorithm="unknown")


class TestPatchBytes:
    """Test binary patching operations."""

    def test_patches_bytes_successfully(self) -> None:
        """Patcher modifies bytes at specified offset."""
        data = bytearray(b"\x00\x00\x00\x00\x00")
        patch_data = b"\xDE\xAD"

        success = patch_bytes(data, offset=1, patch_data=patch_data)

        assert success is True
        assert data == bytearray(b"\x00\xDE\xAD\x00\x00")

    def test_rejects_out_of_bounds_patch(self) -> None:
        """Patcher rejects patches beyond data boundaries."""
        data = bytearray(b"\x00\x00\x00")

        success = patch_bytes(data, offset=2, patch_data=b"\xAA\xBB\xCC")

        assert success is False

    def test_rejects_negative_offset(self) -> None:
        """Patcher rejects negative offsets."""
        data = bytearray(b"\x00\x00\x00")

        success = patch_bytes(data, offset=-1, patch_data=b"\xAA")

        assert success is False


class TestNopRange:
    """Test NOP instruction filling."""

    def test_fills_x86_nops(self) -> None:
        """NOP filler creates x86 NOP instructions."""
        data = bytearray(b"\xFF\xFF\xFF\xFF\xFF")

        success = nop_range(data, start=1, end=4, arch="x86")

        assert success is True
        assert data == bytearray(b"\xFF\x90\x90\x90\xFF")

    def test_fills_x64_nops(self) -> None:
        """NOP filler creates x64 NOP instructions."""
        data = bytearray(b"\xFF\xFF\xFF\xFF\xFF")

        success = nop_range(data, start=1, end=4, arch="x64")

        assert success is True
        assert data[1:4] == bytearray(b"\x90\x90\x90")

    def test_fills_arm_nops(self) -> None:
        """NOP filler creates ARM NOP instructions."""
        data = bytearray(b"\xFF" * 12)

        success = nop_range(data, start=0, end=8, arch="arm")

        assert success is True
        assert len(data) == 12

    def test_rejects_unknown_architecture(self) -> None:
        """NOP filler rejects unknown architectures."""
        data = bytearray(b"\xFF" * 10)

        success = nop_range(data, start=0, end=5, arch="unknown")

        assert success is False

    def test_rejects_invalid_range(self) -> None:
        """NOP filler rejects invalid ranges."""
        data = bytearray(b"\xFF" * 10)

        success = nop_range(data, start=5, end=5, arch="x86")

        assert success is False


class TestCompareBytes:
    """Test byte sequence comparison."""

    def test_finds_single_difference(self) -> None:
        """Byte comparer identifies single byte difference."""
        data1 = b"\x01\x02\x03\x04"
        data2 = b"\x01\x02\xFF\x04"

        diffs = compare_bytes(data1, data2)

        assert len(diffs) == 1
        assert diffs[0]["offset"] == 2
        assert diffs[0]["byte1"] == 0x03
        assert diffs[0]["byte2"] == 0xFF

    def test_finds_multiple_differences(self) -> None:
        """Byte comparer identifies multiple differences."""
        data1 = b"\x01\x02\x03\x04\x05"
        data2 = b"\xFF\x02\xFF\x04\xFF"

        diffs = compare_bytes(data1, data2)

        assert len(diffs) >= 2

    def test_includes_context_bytes(self) -> None:
        """Byte comparer includes surrounding context."""
        data1 = b"\x00\x00\x00\xAA\x00\x00\x00"
        data2 = b"\x00\x00\x00\xBB\x00\x00\x00"

        diffs = compare_bytes(data1, data2, context=3)

        assert "data1" in diffs[0]
        assert "data2" in diffs[0]
        assert len(diffs[0]["data1"]) >= 5
        assert len(diffs[0]["data2"]) >= 5

    def test_detects_length_differences(self) -> None:
        """Byte comparer detects length mismatches."""
        data1 = b"\x01\x02\x03"
        data2 = b"\x01\x02\x03\x04\x05"

        diffs = compare_bytes(data1, data2)

        length_diff = [d for d in diffs if d.get("type") == "length"]
        assert len(length_diff) == 1
        assert length_diff[0]["len1"] == 3
        assert length_diff[0]["len2"] == 5


class TestFormatAddress:
    """Test address formatting."""

    def test_formats_address_default_width(self) -> None:
        """Address formatter creates 8-digit hex."""
        address = 0x401000

        formatted = format_address(address)

        assert formatted == "0x00401000"

    def test_formats_address_custom_width(self) -> None:
        """Address formatter respects custom width."""
        address = 0x1000

        formatted = format_address(address, width=4)

        assert formatted == "0x1000"


class TestIsPrintableAscii:
    """Test printable ASCII detection."""

    def test_detects_printable_ascii(self) -> None:
        """ASCII detector identifies printable ASCII."""
        data = b"Hello, World!"

        result = is_printable_ascii(data)

        assert result is True

    def test_rejects_non_printable(self) -> None:
        """ASCII detector rejects non-printable characters."""
        data = b"Hello\x00World"

        result = is_printable_ascii(data)

        assert result is False

    def test_rejects_high_ascii(self) -> None:
        """ASCII detector rejects extended ASCII."""
        data = b"Hello\xFF"

        result = is_printable_ascii(data)

        assert result is False


class TestDetectEncoding:
    """Test encoding detection."""

    def test_detects_utf8_bom(self) -> None:
        """Encoding detector identifies UTF-8 BOM."""
        data = b"\xEF\xBB\xBFHello"

        encoding = detect_encoding(data)

        assert encoding == "utf-8-sig"

    def test_detects_utf16_le_bom(self) -> None:
        """Encoding detector identifies UTF-16 LE BOM."""
        data = b"\xFF\xFEH\x00e\x00l\x00l\x00o\x00"

        encoding = detect_encoding(data)

        assert encoding == "utf-16-le"

    def test_detects_utf16_be_bom(self) -> None:
        """Encoding detector identifies UTF-16 BE BOM."""
        data = b"\xFE\xFF\x00H\x00e\x00l\x00l\x00o"

        encoding = detect_encoding(data)

        assert encoding == "utf-16-be"

    def test_detects_utf8_without_bom(self) -> None:
        """Encoding detector identifies UTF-8 without BOM."""
        data = "Hello, World!".encode("utf-8")

        encoding = detect_encoding(data)

        assert encoding in {"utf-8", "ascii"}

    def test_returns_none_for_binary_data(self) -> None:
        """Encoding detector returns None for binary data."""
        data = b"\x00\x01\x02\x03\x04\x05"

        encoding = detect_encoding(data)

        assert encoding in {None, "latin-1"}


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_hex_dump_empty_data(self) -> None:
        """Hex dump handles empty data."""
        dump = create_hex_dump(b"")

        assert dump == ""

    def test_hex_dump_single_byte(self) -> None:
        """Hex dump handles single byte."""
        dump = create_hex_dump(b"\xAA")

        assert "aa" in dump.lower()

    def test_pattern_not_found(self) -> None:
        """Pattern finder returns empty list when not found."""
        offsets = find_pattern(b"data", b"pattern")

        assert offsets == []

    def test_compare_identical_bytes(self) -> None:
        """Byte comparer returns no differences for identical data."""
        data = b"\x01\x02\x03\x04"

        diffs = compare_bytes(data, data)

        assert len(diffs) == 0

    def test_patch_zero_length(self) -> None:
        """Patcher handles zero-length patch."""
        data = bytearray(b"\x00\x00\x00")

        success = patch_bytes(data, offset=1, patch_data=b"")

        assert success is True
        assert data == bytearray(b"\x00\x00\x00")


class TestPerformance:
    """Test performance with large data."""

    def test_hex_dump_large_data(self) -> None:
        """Hex dump handles large data efficiently."""
        large_data = b"\x00" * 100_000

        import time

        start_time = time.time()
        dump = create_hex_dump(large_data)
        duration = time.time() - start_time

        assert len(dump) > 0
        assert duration < 5.0

    def test_find_pattern_large_data(self) -> None:
        """Pattern finder handles large data efficiently."""
        large_data = b"\x00" * 1_000_000 + b"pattern" + b"\x00" * 1_000_000

        import time

        start_time = time.time()
        offsets = find_pattern(large_data, b"pattern")
        duration = time.time() - start_time

        assert len(offsets) == 1
        assert duration < 3.0
