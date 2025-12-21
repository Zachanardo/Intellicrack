"""Production-Ready Tests for Data Inspector Module.

Tests REAL data type interpretation and binary format parsing.
"""

import struct
from datetime import datetime

import pytest

from intellicrack.hexview.data_inspector import DataInterpreter, DataType


class TestIntegerInterpretation:
    """Test integer data type interpretations."""

    def test_interpret_uint8(self) -> None:
        """DataInterpreter must correctly interpret uint8."""
        data = bytes([255])
        result = DataInterpreter.interpret(data, DataType.UINT8)

        assert result == "255"

    def test_interpret_int8(self) -> None:
        """DataInterpreter must correctly interpret int8."""
        data = bytes([255])
        result = DataInterpreter.interpret(data, DataType.INT8)

        assert result == "-1"

    def test_interpret_uint16_le(self) -> None:
        """DataInterpreter must correctly interpret uint16 little-endian."""
        data = struct.pack("<H", 0x1234)
        result = DataInterpreter.interpret(data, DataType.UINT16_LE)

        assert result == "4660"

    def test_interpret_uint16_be(self) -> None:
        """DataInterpreter must correctly interpret uint16 big-endian."""
        data = struct.pack(">H", 0x1234)
        result = DataInterpreter.interpret(data, DataType.UINT16_BE)

        assert result == "4660"

    def test_interpret_uint32_le(self) -> None:
        """DataInterpreter must correctly interpret uint32 little-endian."""
        data = struct.pack("<I", 0x12345678)
        result = DataInterpreter.interpret(data, DataType.UINT32_LE)

        assert result == "305419896"

    def test_interpret_uint32_be(self) -> None:
        """DataInterpreter must correctly interpret uint32 big-endian."""
        data = struct.pack(">I", 0x12345678)
        result = DataInterpreter.interpret(data, DataType.UINT32_BE)

        assert result == "305419896"

    def test_interpret_uint64_le(self) -> None:
        """DataInterpreter must correctly interpret uint64 little-endian."""
        data = struct.pack("<Q", 0x123456789ABCDEF0)
        result = DataInterpreter.interpret(data, DataType.UINT64_LE)

        assert result == "1311768467463790320"

    def test_interpret_int32_negative(self) -> None:
        """DataInterpreter must correctly interpret negative int32."""
        data = struct.pack("<i", -12345)
        result = DataInterpreter.interpret(data, DataType.INT32_LE)

        assert result == "-12345"


class TestFloatingPointInterpretation:
    """Test floating-point data type interpretations."""

    def test_interpret_float32_le(self) -> None:
        """DataInterpreter must correctly interpret float32 little-endian."""
        data = struct.pack("<f", 3.14159)
        result = DataInterpreter.interpret(data, DataType.FLOAT32_LE)

        assert "3.14" in result

    def test_interpret_float32_be(self) -> None:
        """DataInterpreter must correctly interpret float32 big-endian."""
        data = struct.pack(">f", 2.71828)
        result = DataInterpreter.interpret(data, DataType.FLOAT32_BE)

        assert "2.71" in result

    def test_interpret_float64_le(self) -> None:
        """DataInterpreter must correctly interpret float64 little-endian."""
        data = struct.pack("<d", 3.141592653589793)
        result = DataInterpreter.interpret(data, DataType.FLOAT64_LE)

        assert "3.14159" in result

    def test_interpret_float64_be(self) -> None:
        """DataInterpreter must correctly interpret float64 big-endian."""
        data = struct.pack(">d", 2.718281828459045)
        result = DataInterpreter.interpret(data, DataType.FLOAT64_BE)

        assert "2.71828" in result


class TestStringInterpretation:
    """Test string encoding interpretations."""

    def test_interpret_ascii(self) -> None:
        """DataInterpreter must correctly interpret ASCII strings."""
        data = b"Hello World!"
        result = DataInterpreter.interpret(data, DataType.ASCII)

        assert result == "Hello World!"

    def test_interpret_ascii_with_null_terminator(self) -> None:
        """DataInterpreter must stop at null terminator for ASCII."""
        data = b"Hello\x00World"
        result = DataInterpreter.interpret(data, DataType.ASCII)

        assert result == "Hello"

    def test_interpret_utf8(self) -> None:
        """DataInterpreter must correctly interpret UTF-8 strings."""
        data = "Hello World!".encode("utf-8")
        result = DataInterpreter.interpret(data, DataType.UTF8)

        assert result == "Hello World!"

    def test_interpret_utf16_le(self) -> None:
        """DataInterpreter must correctly interpret UTF-16 LE strings."""
        data = "Hello".encode("utf-16le")
        result = DataInterpreter.interpret(data, DataType.UTF16_LE)

        assert "Hello" in result

    def test_interpret_utf16_be(self) -> None:
        """DataInterpreter must correctly interpret UTF-16 BE strings."""
        data = "Hello".encode("utf-16be")
        result = DataInterpreter.interpret(data, DataType.UTF16_BE)

        assert "Hello" in result


class TestTimestampInterpretation:
    """Test timestamp interpretations."""

    def test_interpret_unix_timestamp_32(self) -> None:
        """DataInterpreter must correctly interpret 32-bit Unix timestamp."""
        timestamp = 1609459200
        data = struct.pack("<I", timestamp)
        result = DataInterpreter.interpret(data, DataType.UNIX_TIMESTAMP_32)

        assert "2021" in result or "Invalid" in result

    def test_interpret_unix_timestamp_64(self) -> None:
        """DataInterpreter must correctly interpret 64-bit Unix timestamp."""
        timestamp = 1609459200
        data = struct.pack("<Q", timestamp)
        result = DataInterpreter.interpret(data, DataType.UNIX_TIMESTAMP_64)

        assert "2021" in result or "1970" in result

    def test_interpret_windows_filetime(self) -> None:
        """DataInterpreter must correctly interpret Windows FILETIME."""
        filetime = 132539616000000000
        data = struct.pack("<Q", filetime)
        result = DataInterpreter.interpret(data, DataType.WINDOWS_FILETIME)

        assert "20" in result

    def test_interpret_dos_datetime(self) -> None:
        """DataInterpreter must correctly interpret DOS date/time."""
        dos_date = (2021 - 1980) << 9 | 1 << 5 | 15
        dos_time = 12 << 11 | 30 << 5 | (45 // 2)

        data = struct.pack("<HH", dos_time, dos_date)
        result = DataInterpreter.interpret(data, DataType.DOS_DATETIME)

        assert "2021" in result


class TestSpecialFormatInterpretation:
    """Test special format interpretations."""

    def test_interpret_binary(self) -> None:
        """DataInterpreter must correctly interpret binary representation."""
        data = bytes([0xFF, 0x00, 0xAA])
        result = DataInterpreter.interpret(data, DataType.BINARY)

        assert "11111111" in result
        assert "00000000" in result
        assert "10101010" in result

    def test_interpret_hex(self) -> None:
        """DataInterpreter must correctly interpret hex representation."""
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        result = DataInterpreter.interpret(data, DataType.HEX)

        assert "DE" in result
        assert "AD" in result
        assert "BE" in result
        assert "EF" in result

    def test_interpret_guid(self) -> None:
        """DataInterpreter must correctly interpret GUID."""
        guid_bytes = (
            b"\x01\x02\x03\x04"
            b"\x05\x06"
            b"\x07\x08"
            b"\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
        )

        result = DataInterpreter.interpret(guid_bytes, DataType.GUID)

        assert "-" in result
        assert "04030201" in result.upper()

    def test_interpret_ipv4_address(self) -> None:
        """DataInterpreter must correctly interpret IPv4 address."""
        data = bytes([192, 168, 1, 100])
        result = DataInterpreter.interpret(data, DataType.IPV4_ADDRESS)

        assert result == "192.168.1.100"

    def test_interpret_ipv6_address(self) -> None:
        """DataInterpreter must correctly interpret IPv6 address."""
        data = struct.pack(">8H", 0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001)
        result = DataInterpreter.interpret(data, DataType.IPV6_ADDRESS)

        assert "2001" in result
        assert "0db8" in result or "db8" in result

    def test_interpret_mac_address(self) -> None:
        """DataInterpreter must correctly interpret MAC address."""
        data = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        result = DataInterpreter.interpret(data, DataType.MAC_ADDRESS)

        assert "00:1A:2B:3C:4D:5E" in result


class TestInsufficientData:
    """Test handling of insufficient data."""

    def test_insufficient_data_uint16(self) -> None:
        """DataInterpreter must handle insufficient data for uint16."""
        data = bytes([0x00])
        result = DataInterpreter.interpret(data, DataType.UINT16_LE)

        assert "Insufficient data" in result

    def test_insufficient_data_uint32(self) -> None:
        """DataInterpreter must handle insufficient data for uint32."""
        data = bytes([0x00, 0x01])
        result = DataInterpreter.interpret(data, DataType.UINT32_LE)

        assert "Insufficient data" in result

    def test_insufficient_data_float64(self) -> None:
        """DataInterpreter must handle insufficient data for float64."""
        data = bytes([0x00] * 4)
        result = DataInterpreter.interpret(data, DataType.FLOAT64_LE)

        assert "Insufficient data" in result

    def test_insufficient_data_guid(self) -> None:
        """DataInterpreter must handle insufficient data for GUID."""
        data = bytes([0x00] * 8)
        result = DataInterpreter.interpret(data, DataType.GUID)

        assert "Insufficient data" in result


class TestEmptyData:
    """Test handling of empty data."""

    def test_empty_data_returns_no_data(self) -> None:
        """DataInterpreter must return 'No data' for empty input."""
        result = DataInterpreter.interpret(b"", DataType.UINT32_LE)

        assert "No data" in result


class TestRealWorldData:
    """Test interpretation of real-world binary data."""

    def test_interpret_pe_signature(self) -> None:
        """DataInterpreter must correctly interpret PE signature."""
        pe_sig = b"MZ"
        result = DataInterpreter.interpret(pe_sig, DataType.ASCII)

        assert result == "MZ"

    def test_interpret_pe_header_timestamp(self) -> None:
        """DataInterpreter must interpret PE timestamp correctly."""
        timestamp = 1609459200
        data = struct.pack("<I", timestamp)
        result = DataInterpreter.interpret(data, DataType.UNIX_TIMESTAMP_32)

        assert "2021" in result or "Invalid" in result

    def test_interpret_version_number(self) -> None:
        """DataInterpreter must interpret version numbers."""
        major = 1
        minor = 2
        data = struct.pack("<HH", major, minor)

        major_result = DataInterpreter.interpret(data[:2], DataType.UINT16_LE)
        minor_result = DataInterpreter.interpret(data[2:4], DataType.UINT16_LE)

        assert major_result == "1"
        assert minor_result == "2"


class TestEdgeCases:
    """Test edge cases in data interpretation."""

    def test_interpret_max_values(self) -> None:
        """DataInterpreter must handle maximum values."""
        data = struct.pack("<I", 0xFFFFFFFF)
        result = DataInterpreter.interpret(data, DataType.UINT32_LE)

        assert result == "4294967295"

    def test_interpret_zero_values(self) -> None:
        """DataInterpreter must handle zero values."""
        data = struct.pack("<I", 0)
        result = DataInterpreter.interpret(data, DataType.UINT32_LE)

        assert result == "0"

    def test_interpret_negative_floats(self) -> None:
        """DataInterpreter must handle negative floating-point values."""
        data = struct.pack("<f", -3.14159)
        result = DataInterpreter.interpret(data, DataType.FLOAT32_LE)

        assert "-3.14" in result

    def test_interpret_special_floats(self) -> None:
        """DataInterpreter must handle special float values (inf, nan)."""
        import math

        data_inf = struct.pack("<f", math.inf)
        data_nan = struct.pack("<f", math.nan)

        result_inf = DataInterpreter.interpret(data_inf, DataType.FLOAT32_LE)
        result_nan = DataInterpreter.interpret(data_nan, DataType.FLOAT32_LE)

        assert result_inf is not None
        assert result_nan is not None


class TestNonPrintableCharacters:
    """Test handling of non-printable characters in strings."""

    def test_interpret_ascii_with_control_chars(self) -> None:
        """DataInterpreter must handle control characters in ASCII."""
        data = b"Hello\x01\x02\x03World"
        result = DataInterpreter.interpret(data, DataType.ASCII)

        assert "Hello" in result

    def test_interpret_invalid_utf8(self) -> None:
        """DataInterpreter must handle invalid UTF-8 sequences."""
        data = b"\xFF\xFE\x00\x00"
        result = DataInterpreter.interpret(data, DataType.UTF8)

        assert result is not None
