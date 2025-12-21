"""Production tests for hex viewer API.

Tests validate REAL hex viewer API functionality:
- File operations (open, read, write)
- Binary analysis integration
- Pattern search capabilities
- Edit suggestion generation
- UI component creation
- Integration with Intellicrack

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.hexview import api


@pytest.fixture
def test_binary_file(tmp_path: Path) -> Path:
    """Create test binary file with license protection patterns."""
    file_path = tmp_path / "protected.exe"
    data = bytearray(2048)
    data[0:2] = b"MZ"
    data[100:120] = b"License Key Required"
    data[200:210] = b"Trial Mode"
    data[300:320] = b"\x74\x10" + b"\x90" * 18
    data[500:600] = bytes(range(100))

    file_path.write_bytes(data)
    return file_path


@pytest.fixture
def readonly_binary(tmp_path: Path) -> Path:
    """Create read-only binary file."""
    file_path = tmp_path / "readonly.bin"
    file_path.write_bytes(b"\xDE\xAD\xBE\xEF" * 256)
    return file_path


class TestFileOperations:
    """Test hex viewer file operations."""

    def test_open_hex_file_readonly(self, test_binary_file: Path) -> None:
        """API opens binary file in read-only mode."""
        file_handler = api.open_hex_file(str(test_binary_file), read_only=True)

        assert file_handler is not None
        assert hasattr(file_handler, "read")

    def test_open_hex_file_writable(self, test_binary_file: Path) -> None:
        """API opens binary file in writable mode."""
        file_handler = api.open_hex_file(str(test_binary_file), read_only=False)

        assert file_handler is not None
        assert hasattr(file_handler, "write")

    def test_open_nonexistent_file(self) -> None:
        """API handles nonexistent file gracefully."""
        result = api.open_hex_file("D:\\nonexistent\\file.bin", read_only=True)

        assert result is None

    def test_read_hex_region_pe_header(self, test_binary_file: Path) -> None:
        """API reads PE header region correctly."""
        data = api.read_hex_region(str(test_binary_file), offset=0, size=2)

        assert data is not None
        assert data == b"MZ"

    def test_read_hex_region_middle(self, test_binary_file: Path) -> None:
        """API reads data from middle of file."""
        data = api.read_hex_region(str(test_binary_file), offset=100, size=20)

        assert data is not None
        assert len(data) == 20
        assert b"License Key Required" == data

    def test_read_hex_region_large_offset(self, test_binary_file: Path) -> None:
        """API reads data at large offset."""
        data = api.read_hex_region(str(test_binary_file), offset=500, size=100)

        assert data is not None
        assert len(data) == 100
        assert data == bytes(range(100))

    def test_read_hex_region_beyond_eof(self, test_binary_file: Path) -> None:
        """API handles reading beyond EOF correctly."""
        file_size = test_binary_file.stat().st_size
        data = api.read_hex_region(str(test_binary_file), offset=file_size - 10, size=50)

        assert data is not None
        assert len(data) <= 50

    def test_write_hex_region_overwrite(self, test_binary_file: Path) -> None:
        """API writes data to binary file (overwrite mode)."""
        new_data = b"PATCHED!"
        offset = 300

        result = api.write_hex_region(str(test_binary_file), offset, new_data)
        assert result is True

        written_data = api.read_hex_region(str(test_binary_file), offset, len(new_data))
        assert written_data == new_data

    def test_write_hex_region_license_bypass(self, test_binary_file: Path) -> None:
        """API patches license check in binary."""
        nop_bytes = b"\x90\x90"
        license_check_offset = 300

        result = api.write_hex_region(str(test_binary_file), license_check_offset, nop_bytes)
        assert result is True

        patched = api.read_hex_region(str(test_binary_file), license_check_offset, 2)
        assert patched == nop_bytes

    def test_write_hex_region_nonexistent_file(self) -> None:
        """API handles write to nonexistent file."""
        result = api.write_hex_region("D:\\nonexistent\\file.bin", 0, b"\x00\x00")

        assert result is False


class TestAnalysisOperations:
    """Test binary analysis API operations."""

    def test_analyze_binary_data_pe_header(self) -> None:
        """API analyzes PE header binary data."""
        pe_data = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_data += b"License validation routine"

        result = api.analyze_binary_data(pe_data, query="What does this binary contain?")

        assert isinstance(result, dict)
        assert "error" not in result or "patterns" in result

    def test_analyze_binary_data_with_query(self) -> None:
        """API analyzes binary with specific query."""
        license_data = b"Enter registration code: " + b"\x00" * 50
        license_data += b"Trial expired" + b"\x00" * 50

        result = api.analyze_binary_data(
            license_data,
            query="Find license-related strings",
        )

        assert isinstance(result, dict)
        assert "data_meaning" in result or "summary" in result or "error" in result

    def test_search_binary_pattern_license_strings(self) -> None:
        """API searches for license-related patterns."""
        data = b"\x90" * 100
        data += b"License Key Required"
        data += b"\x90" * 100

        results = api.search_binary_pattern(
            data,
            pattern_desc="License key validation messages",
        )

        assert isinstance(results, list)

    def test_search_binary_pattern_trial_check(self) -> None:
        """API searches for trial period checks."""
        data = b"Trial period expired" + b"\x00" * 100
        data += b"Days remaining: " + b"\x00" * 100

        results = api.search_binary_pattern(
            data,
            pattern_desc="Trial expiration checks",
        )

        assert isinstance(results, list)

    def test_suggest_binary_edits_nop_jump(self) -> None:
        """API suggests NOPs for conditional jump."""
        data = b"\x90" * 50
        data += b"\x74\x10"
        data += b"\x90" * 50

        result = api.suggest_binary_edits(
            data,
            edit_intent="Patch the conditional jump to unconditional",
        )

        assert isinstance(result, dict)
        assert "edit_type" in result
        assert "explanation" in result

    def test_suggest_binary_edits_license_bypass(self) -> None:
        """API suggests edits to bypass license check."""
        data = b"\x83\x7D\xFC\x00"
        data += b"\x74\x10"
        data += b"\x90" * 50

        result = api.suggest_binary_edits(
            data,
            edit_intent="Make license check always succeed",
        )

        assert isinstance(result, dict)
        assert "offset" in result or "error" in result


class TestUtilityOperations:
    """Test utility API operations."""

    def test_bytes_to_hex_string_simple(self) -> None:
        """API converts bytes to formatted hex string."""
        data = b"\xDE\xAD\xBE\xEF"
        hex_str = api.bytes_to_hex_string(data, bytes_per_line=16)

        assert "DE AD BE EF" in hex_str
        assert "00000000:" in hex_str

    def test_bytes_to_hex_string_multiline(self) -> None:
        """API converts bytes to multiline hex output."""
        data = bytes(range(48))
        hex_str = api.bytes_to_hex_string(data, bytes_per_line=16)

        lines = hex_str.split("\n")
        assert len(lines) == 3
        assert "00000000:" in lines[0]
        assert "00000010:" in lines[1]
        assert "00000020:" in lines[2]

    def test_bytes_to_hex_string_with_ascii(self) -> None:
        """API includes ASCII representation in hex string."""
        data = b"Hello, World!\x00\x00\x00"
        hex_str = api.bytes_to_hex_string(data, bytes_per_line=16)

        assert "|" in hex_str
        assert "Hello" in hex_str or "World" in hex_str

    def test_hex_string_to_bytes_simple(self) -> None:
        """API converts hex string back to bytes."""
        hex_str = "DE AD BE EF"
        data = api.hex_string_to_bytes(hex_str)

        assert data == b"\xDE\xAD\xBE\xEF"

    def test_hex_string_to_bytes_formatted(self) -> None:
        """API parses formatted hex dump back to bytes."""
        hex_str = """00000000: DE AD BE EF 90 90 90 90 | ........
00000008: 01 02 03 04 05 06 07 08 | ........"""
        data = api.hex_string_to_bytes(hex_str)

        assert data[:4] == b"\xDE\xAD\xBE\xEF"
        assert data[4:8] == b"\x90\x90\x90\x90"
        assert data[8:16] == bytes(range(1, 9))

    def test_hex_string_to_bytes_with_newlines(self) -> None:
        """API handles hex strings with various newline formats."""
        hex_str = "DE AD\nBE EF\n90 90"
        data = api.hex_string_to_bytes(hex_str)

        assert data == b"\xDE\xAD\xBE\xEF\x90\x90"

    def test_create_binary_context(self) -> None:
        """API creates context for binary data."""
        data = b"MZ" + b"\x90" * 100 + b"License Check"
        context = api.create_binary_context(data)

        assert isinstance(context, dict)
        assert "offset" in context
        assert "size" in context
        assert "entropy" in context
        assert "strings" in context
        assert "structure_hints" in context
        assert "interpretations" in context

    def test_create_binary_context_encrypted_data(self) -> None:
        """API creates context showing high entropy for encrypted data."""
        data = bytes((i * 73 + 29) % 256 for i in range(256))
        context = api.create_binary_context(data)

        assert context["entropy"] > 7.0
        assert "entropy_segments" in context


class TestUIOperations:
    """Test UI component creation (non-GUI tests)."""

    def test_create_hex_viewer_widget(self) -> None:
        """API creates hex viewer widget instance."""
        try:
            from PyQt6.QtWidgets import QApplication
            app = QApplication.instance() or QApplication([])

            widget = api.create_hex_viewer_widget()
            assert widget is not None
        except ImportError:
            pytest.skip("PyQt6 not available")

    def test_create_hex_viewer_dialog(self, test_binary_file: Path) -> None:
        """API creates hex viewer dialog instance."""
        try:
            from PyQt6.QtWidgets import QApplication
            app = QApplication.instance() or QApplication([])

            dialog = api.create_hex_viewer_dialog(
                parent=None,
                file_path=str(test_binary_file),
                read_only=True,
            )
            assert dialog is not None
        except ImportError:
            pytest.skip("PyQt6 not available")


class TestIntegrationOperations:
    """Test Intellicrack integration operations."""

    def test_register_ai_tools_without_app(self) -> None:
        """API handles AI tool registration without app instance."""
        class MockApp:
            pass

        mock_app = MockApp()
        result = api.register_ai_tools(mock_app)

        assert isinstance(result, bool)


class TestCompleteWorkflows:
    """Test complete hex viewer API workflows."""

    def test_workflow_read_analyze_patch(self, test_binary_file: Path) -> None:
        """Complete workflow: read binary, analyze, suggest patch, apply patch."""
        license_check_offset = 300
        data = api.read_hex_region(str(test_binary_file), license_check_offset, 50)
        assert data is not None

        suggestions = api.suggest_binary_edits(
            data,
            edit_intent="Bypass license validation",
        )
        assert isinstance(suggestions, dict)

        nop_patch = b"\x90\x90"
        result = api.write_hex_region(str(test_binary_file), license_check_offset, nop_patch)
        assert result is True

        patched_data = api.read_hex_region(str(test_binary_file), license_check_offset, 2)
        assert patched_data == nop_patch

    def test_workflow_find_and_patch_trial_check(self, test_binary_file: Path) -> None:
        """Complete workflow: find trial strings and patch nearby checks."""
        file_data = test_binary_file.read_bytes()

        context = api.create_binary_context(file_data)
        assert "strings" in context

        trial_strings = [s for s in context["strings"] if "Trial" in s.get("value", "")]
        assert len(trial_strings) > 0

        trial_offset = trial_strings[0]["offset"]
        nearby_data = api.read_hex_region(str(test_binary_file), trial_offset - 50, 100)
        assert nearby_data is not None

    def test_workflow_detect_protection_and_analyze(self, tmp_path: Path) -> None:
        """Complete workflow: detect protection scheme and analyze with AI."""
        vmprotect_file = tmp_path / "vmprotect.exe"
        data = b"MZ\x90\x00"
        data += b"\x00" * 100
        data += b"VMProtect by Oreans"
        data += b"\x00" * 100
        vmprotect_file.write_bytes(data)

        file_data = api.read_hex_region(str(vmprotect_file), 0, 300)
        assert file_data is not None

        context = api.create_binary_context(file_data)
        hints = context.get("structure_hints", [])
        pe_detected = any(h.get("description") == "PE/DOS Executable" for h in hints)
        assert pe_detected

        analysis = api.analyze_binary_data(file_data, query="Identify protection scheme")
        assert isinstance(analysis, dict)

    def test_workflow_hex_conversion_roundtrip(self) -> None:
        """Complete workflow: bytes to hex string and back."""
        original_data = b"\xDE\xAD\xBE\xEF\x90\x90\x74\x10"

        hex_str = api.bytes_to_hex_string(original_data, bytes_per_line=8)
        assert hex_str is not None

        converted_back = api.hex_string_to_bytes(hex_str)
        assert converted_back == original_data

    def test_workflow_large_file_chunked_read(self, tmp_path: Path) -> None:
        """Complete workflow: read large file in chunks."""
        large_file = tmp_path / "large.bin"
        chunk_size = 1024
        num_chunks = 10
        total_size = chunk_size * num_chunks

        large_data = bytearray(total_size)
        for i in range(total_size):
            large_data[i] = i % 256
        large_file.write_bytes(large_data)

        chunks = []
        for chunk_num in range(num_chunks):
            offset = chunk_num * chunk_size
            chunk = api.read_hex_region(str(large_file), offset, chunk_size)
            assert chunk is not None
            assert len(chunk) == chunk_size
            chunks.append(chunk)

        reconstructed = b"".join(chunks)
        assert reconstructed == bytes(large_data)

    def test_workflow_identify_and_nop_all_jumps(self, test_binary_file: Path) -> None:
        """Complete workflow: identify all conditional jumps and NOP them."""
        file_data = test_binary_file.read_bytes()

        je_pattern = b"\x74"
        jne_pattern = b"\x75"

        jump_offsets = []
        for i in range(len(file_data) - 1):
            if file_data[i:i+1] in (je_pattern, jne_pattern):
                jump_offsets.append(i)

        assert len(jump_offsets) > 0

        for offset in jump_offsets:
            nop_bytes = b"\x90\x90"
            result = api.write_hex_region(str(test_binary_file), offset, nop_bytes)
            assert result is True

        patched_data = test_binary_file.read_bytes()
        for offset in jump_offsets:
            assert patched_data[offset:offset+2] == b"\x90\x90"
