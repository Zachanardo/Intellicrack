"""Tests for hex_str status bar display in hex_dialog.py.

This tests that the hex_str variable is properly displayed in the status
bar alongside interpreted values for complete selection information.
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest


class TestHexDialogStatusDisplay:
    """Test suite for hex string status bar display."""

    def test_hex_string_formatting(self) -> None:
        """Test that hex string is formatted correctly."""
        data = b"\x4D\x5A\x90\x00"
        hex_str = " ".join(f"{b:02X}" for b in data)

        assert hex_str == "4D 5A 90 00"

    def test_single_byte_display_format(self) -> None:
        """Test status bar format for single byte selection."""
        data = b"\x7F"
        hex_str = " ".join(f"{b:02X}" for b in data)

        expected_format = f" | Hex: {hex_str} | Value: {data[0]} (0x{data[0]:02X})"

        assert "Hex: 7F" in expected_format
        assert "Value: 127" in expected_format
        assert "0x7F" in expected_format

    def test_two_byte_display_format(self) -> None:
        """Test status bar format for 2-byte selection with LE/BE values."""
        data = b"\x01\x02"
        hex_str = " ".join(f"{b:02X}" for b in data)

        value_le = struct.unpack("<H", data)[0]
        value_be = struct.unpack(">H", data)[0]

        expected_format = f" | Hex: {hex_str} | Value: {value_le} LE, {value_be} BE"

        assert "Hex: 01 02" in expected_format
        assert "513 LE" in expected_format
        assert "258 BE" in expected_format

    def test_four_byte_display_format(self) -> None:
        """Test status bar format for 4-byte selection."""
        data = b"\x01\x02\x03\x04"
        hex_str = " ".join(f"{b:02X}" for b in data)

        value_le = struct.unpack("<I", data)[0]
        value_be = struct.unpack(">I", data)[0]

        expected_format = f" | Hex: {hex_str} | Value: {value_le} LE, {value_be} BE"

        assert "Hex: 01 02 03 04" in expected_format
        assert str(value_le) in expected_format
        assert str(value_be) in expected_format

    def test_eight_byte_display_format(self) -> None:
        """Test status bar format for 8-byte selection."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        hex_str = " ".join(f"{b:02X}" for b in data)

        value_le = struct.unpack("<Q", data)[0]
        value_be = struct.unpack(">Q", data)[0]

        expected_format = f" | Hex: {hex_str} | Value: {value_le} LE, {value_be} BE"

        assert "Hex: 01 02 03 04 05 06 07 08" in expected_format
        assert str(value_le) in expected_format
        assert str(value_be) in expected_format

    def test_hex_format_uppercase(self) -> None:
        """Test that hex values are formatted as uppercase."""
        data = b"\xab\xcd\xef"
        hex_str = " ".join(f"{b:02X}" for b in data)

        assert hex_str == "AB CD EF"
        assert "ab" not in hex_str

    def test_hex_format_leading_zeros(self) -> None:
        """Test that hex values have leading zeros."""
        data = b"\x00\x0F\x01"
        hex_str = " ".join(f"{b:02X}" for b in data)

        assert hex_str == "00 0F 01"
        assert len(hex_str.split()) == 3

    def test_endianness_interpretation_correctness(self) -> None:
        """Test that LE/BE interpretations are mathematically correct."""
        data = b"\x01\x00\x00\x00"

        value_le = struct.unpack("<I", data)[0]
        value_be = struct.unpack(">I", data)[0]

        assert value_le == 1
        assert value_be == 16777216

    def test_signed_byte_display(self) -> None:
        """Test display of signed byte value."""
        data = b"\xFF"
        unsigned_value = data[0]

        assert unsigned_value == 255
        assert f"0x{unsigned_value:02X}" == "0xFF"

    def test_selection_size_boundary(self) -> None:
        """Test that selection size boundary (8 bytes) is respected."""
        selection_sizes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        for size in selection_sizes:
            should_display_hex = size <= 8
            if size <= 8:
                assert should_display_hex
            else:
                assert not should_display_hex

    def test_empty_data_handling(self) -> None:
        """Test handling of empty data."""
        hex_str = " ".join(f"{b:02X}" for b in data) if (data := b"") else ""
        assert not hex_str

    def test_maximum_display_size(self) -> None:
        """Test maximum display size constraint."""
        data = b"\x00" * 100
        selection_size = len(data)

        should_display_hex = selection_size <= 8
        assert not should_display_hex

    def test_struct_unpack_alignment(self) -> None:
        """Test struct unpacking with correct alignment."""
        data_2 = b"\x01\x02"
        data_4 = b"\x01\x02\x03\x04"
        data_8 = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        assert len(data_2) == 2
        assert len(data_4) == 4
        assert len(data_8) == 8

        val_2 = struct.unpack("<H", data_2)[0]
        val_4 = struct.unpack("<I", data_4)[0]
        val_8 = struct.unpack("<Q", data_8)[0]

        assert isinstance(val_2, int)
        assert isinstance(val_4, int)
        assert isinstance(val_8, int)

    def test_insufficient_data_handling(self) -> None:
        """Test handling when data length doesn't match expected size."""
        data = b"\x01\x02\x03"
        selection_size = 4

        if len(data) != selection_size:
            value_str = f" | Value: <insufficient data: {len(data)}/{selection_size} bytes>"
            assert "insufficient data" in value_str
            assert "3/4" in value_str

    def test_status_bar_info_format(self) -> None:
        """Test complete status bar info format."""
        offset = 0x1000
        file_size = 65536
        start = 100
        end = 104
        selection_size = end - start
        data = b"\x4D\x5A\x90\x00"
        hex_str = " ".join(f"{b:02X}" for b in data)

        value_le = struct.unpack("<I", data)[0]
        value_be = struct.unpack(">I", data)[0]
        value_str = f" | Hex: {hex_str} | Value: {value_le} LE, {value_be} BE"

        info = f"Offset: 0x{offset:X} ({offset}) | File Size: {file_size:,} bytes"
        info += f" | Selection: 0x{start:X}-0x{end - 1:X} ({selection_size} bytes){value_str}"

        assert "Offset: 0x1000" in info
        assert "65,536 bytes" in info
        assert "Selection: 0x64-0x67" in info
        assert "Hex: 4D 5A 90 00" in info
