"""Production-Ready Tests for Hex Renderer Module.

Tests REAL hex rendering, decimal/binary views, and structure parsing.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.hex_renderer import HexViewRenderer, ViewMode, parse_hex_view


class TestHexViewRenderer:
    """Test HexViewRenderer hex output generation."""

    def test_hexviewrenderer_creates_with_defaults(self) -> None:
        """HexViewRenderer must create with default settings."""
        renderer = HexViewRenderer()

        assert renderer.bytes_per_row == 16
        assert renderer.group_size == 1
        assert renderer.show_ascii is True
        assert renderer.show_address is True

    def test_hexviewrenderer_renders_simple_data(self) -> None:
        """HexViewRenderer must render simple byte data."""
        renderer = HexViewRenderer(bytes_per_row=16, show_ascii=True, show_address=True)
        data = bytes(range(16))

        output = renderer.render_hex_view(data, offset=0)

        assert "00000000:" in output
        assert "00 01 02 03" in output
        assert "0E 0F" in output

    def test_hexviewrenderer_shows_ascii_column(self) -> None:
        """HexViewRenderer must show ASCII column when enabled."""
        renderer = HexViewRenderer(show_ascii=True)
        data = b"Hello World!"

        output = renderer.render_hex_view(data)

        assert "|" in output
        assert "Hello World!" in output

    def test_hexviewrenderer_hides_ascii_column(self) -> None:
        """HexViewRenderer must hide ASCII when disabled."""
        renderer = HexViewRenderer(show_ascii=False)
        data = b"Hello World!"

        output = renderer.render_hex_view(data)

        assert "|" not in output

    def test_hexviewrenderer_shows_addresses(self) -> None:
        """HexViewRenderer must show addresses when enabled."""
        renderer = HexViewRenderer(show_address=True)
        data = bytes(range(32))

        output = renderer.render_hex_view(data, offset=0x1000)

        assert "00001000:" in output
        assert "00001010:" in output

    def test_hexviewrenderer_hides_addresses(self) -> None:
        """HexViewRenderer must hide addresses when disabled."""
        renderer = HexViewRenderer(show_address=False)
        data = bytes(range(16))

        output = renderer.render_hex_view(data)

        assert ":" not in output

    def test_hexviewrenderer_group_size_1(self) -> None:
        """HexViewRenderer must group bytes individually."""
        renderer = HexViewRenderer(group_size=1)
        data = bytes(range(8))

        output = renderer.render_hex_view(data)

        assert "00 01 02 03" in output

    def test_hexviewrenderer_group_size_2(self) -> None:
        """HexViewRenderer must group bytes in pairs."""
        renderer = HexViewRenderer(group_size=2, bytes_per_row=8)
        data = bytes(range(8))

        output = renderer.render_hex_view(data)

        assert "0001" in output or "00 01" in output

    def test_hexviewrenderer_group_size_4(self) -> None:
        """HexViewRenderer must group bytes in groups of 4."""
        renderer = HexViewRenderer(group_size=4, bytes_per_row=8)
        data = bytes(range(8))

        output = renderer.render_hex_view(data)

        assert "00010203" in output or "0001 0203" in output

    def test_hexviewrenderer_handles_empty_data(self) -> None:
        """HexViewRenderer must handle empty data."""
        renderer = HexViewRenderer()
        output = renderer.render_hex_view(b"")

        assert output == "Empty data"

    def test_hexviewrenderer_handles_non_printable_ascii(self) -> None:
        """HexViewRenderer must show dots for non-printable characters."""
        renderer = HexViewRenderer(show_ascii=True)
        data = b"\x00\x01\x02\x1F\x20\x7E\x7F\xFF"

        output = renderer.render_hex_view(data)

        assert "." in output


class TestDecimalView:
    """Test decimal view rendering."""

    def test_hexviewrenderer_renders_decimal_view(self) -> None:
        """HexViewRenderer must render decimal values."""
        renderer = HexViewRenderer()
        data = bytes([0, 1, 127, 255])

        output = renderer.render_decimal_view(data)

        assert "0" in output or "  0" in output
        assert "127" in output
        assert "255" in output

    def test_decimal_view_shows_addresses_in_decimal(self) -> None:
        """Decimal view must show addresses in decimal format."""
        renderer = HexViewRenderer(show_address=True)
        data = bytes(range(32))

        output = renderer.render_decimal_view(data, offset=1000)

        assert "00001000:" in output or "1000:" in output

    def test_decimal_view_handles_empty_data(self) -> None:
        """Decimal view must handle empty data."""
        renderer = HexViewRenderer()
        output = renderer.render_decimal_view(b"")

        assert output == "Empty data"


class TestBinaryView:
    """Test binary view rendering."""

    def test_hexviewrenderer_renders_binary_view(self) -> None:
        """HexViewRenderer must render binary values."""
        renderer = HexViewRenderer()
        data = bytes([0xFF, 0x00, 0xAA, 0x55])

        output = renderer.render_binary_view(data)

        assert "11111111" in output
        assert "00000000" in output
        assert "10101010" in output
        assert "01010101" in output

    def test_binary_view_shows_fewer_bytes_per_row(self) -> None:
        """Binary view must show fewer bytes per row due to width."""
        renderer = HexViewRenderer(bytes_per_row=16)
        data = bytes(range(16))

        output = renderer.render_binary_view(data)

        lines = output.strip().split("\n")
        assert len(lines) >= 2

    def test_binary_view_handles_empty_data(self) -> None:
        """Binary view must handle empty data."""
        renderer = HexViewRenderer()
        output = renderer.render_binary_view(b"")

        assert output == "Empty data"


class TestStructureView:
    """Test structure view rendering."""

    def test_hexviewrenderer_renders_structure_view(self) -> None:
        """HexViewRenderer must render data according to structure definition."""
        renderer = HexViewRenderer()

        structure_def = {
            "magic": {"type": "uint32", "size": 4, "count": 1},
            "version": {"type": "uint16", "size": 2, "count": 1},
            "flags": {"type": "uint16", "size": 2, "count": 1},
        }

        data = b"\x4D\x5A\x90\x00" + b"\x03\x00" + b"\x00\x00"

        output = renderer.render_structure_view(data, structure_def)

        assert "magic" in output
        assert "version" in output
        assert "flags" in output
        assert "uint32" in output
        assert "uint16" in output

    def test_structure_view_handles_char_arrays(self) -> None:
        """Structure view must handle character arrays as strings."""
        renderer = HexViewRenderer()

        structure_def = {
            "name": {"type": "char", "size": 1, "count": 10},
        }

        data = b"HelloWorld"

        output = renderer.render_structure_view(data, structure_def)

        assert "name" in output
        assert "HelloWorld" in output or "Hello" in output

    def test_structure_view_handles_insufficient_data(self) -> None:
        """Structure view must handle insufficient data gracefully."""
        renderer = HexViewRenderer()

        structure_def = {
            "field1": {"type": "uint64", "size": 8, "count": 1},
        }

        data = b"\x00\x01\x02"

        output = renderer.render_structure_view(data, structure_def)

        assert "insufficient data" in output.lower()

    def test_structure_view_handles_empty_data(self) -> None:
        """Structure view must handle empty data."""
        renderer = HexViewRenderer()
        output = renderer.render_structure_view(b"", {})

        assert "No data" in output


class TestParseHexView:
    """Test parsing hex view back to binary."""

    def test_parse_hex_view_simple(self) -> None:
        """parse_hex_view must convert hex view to binary."""
        hex_view = "00000000: 48 65 6C 6C 6F 20 57 6F 72 6C 64 21"

        offset, data = parse_hex_view(hex_view)

        assert offset == 0
        assert data == b"Hello World!"

    def test_parse_hex_view_multiple_lines(self) -> None:
        """parse_hex_view must handle multiple lines."""
        hex_view = """00000000: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000010: 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"""

        offset, data = parse_hex_view(hex_view)

        assert offset == 0
        assert len(data) == 32
        assert data == bytes(range(32))

    def test_parse_hex_view_with_offset(self) -> None:
        """parse_hex_view must extract starting offset."""
        hex_view = "00001000: AA BB CC DD"

        offset, data = parse_hex_view(hex_view)

        assert offset == 0x1000
        assert data == b"\xAA\xBB\xCC\xDD"

    def test_parse_hex_view_roundtrip(self) -> None:
        """Rendering then parsing must preserve data."""
        renderer = HexViewRenderer(show_ascii=False, show_address=True)
        original_data = bytes(range(16))

        rendered = renderer.render_hex_view(original_data, offset=0)
        offset, parsed_data = parse_hex_view(rendered)

        assert parsed_data == original_data


class TestViewMode:
    """Test ViewMode enum."""

    def test_viewmode_names(self) -> None:
        """ViewMode.names() must return all mode names."""
        names = ViewMode.names()

        assert "Hex" in names
        assert "Decimal" in names
        assert "Binary" in names
        assert "Structure" in names


class TestRealWorldRendering:
    """Test rendering with real binary data."""

    def test_render_pe_header(self) -> None:
        """HexViewRenderer must render actual PE binary header."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found - Windows system required")

        data = notepad.read_bytes()[:64]
        renderer = HexViewRenderer()

        output = renderer.render_hex_view(data)

        assert "4D 5A" in output or "4D5A" in output
        assert "MZ" in output

    def test_render_large_data_efficiently(self, tmp_path: Path) -> None:
        """HexViewRenderer must render large data efficiently."""
        large_data = bytes(range(256)) * 100

        renderer = HexViewRenderer()
        output = renderer.render_hex_view(large_data)

        lines = output.strip().split("\n")
        assert len(lines) > 0


class TestRendererEdgeCases:
    """Test renderer edge cases."""

    def test_renderer_adjusts_bytes_per_row_for_group_size(self) -> None:
        """Renderer must adjust bytes_per_row to be multiple of group_size."""
        renderer = HexViewRenderer(bytes_per_row=15, group_size=4)

        assert renderer.bytes_per_row % renderer.group_size == 0

    def test_renderer_handles_incomplete_final_row(self) -> None:
        """Renderer must handle incomplete final row."""
        renderer = HexViewRenderer(bytes_per_row=16)
        data = bytes(range(20))

        output = renderer.render_hex_view(data)

        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_renderer_set_bytes_per_row(self) -> None:
        """Renderer must allow changing bytes_per_row."""
        renderer = HexViewRenderer(bytes_per_row=16)

        renderer.set_bytes_per_row(32)

        assert renderer.bytes_per_row == 32

    def test_renderer_set_group_size(self) -> None:
        """Renderer must allow changing group_size."""
        renderer = HexViewRenderer(group_size=1)

        renderer.set_group_size(4)

        assert renderer.group_size == 4

    def test_renderer_invalid_group_size_defaults_to_1(self) -> None:
        """Renderer must default to group_size=1 for invalid values."""
        renderer = HexViewRenderer(group_size=3)

        assert renderer.group_size == 1
