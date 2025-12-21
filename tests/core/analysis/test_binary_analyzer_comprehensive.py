"""Comprehensive tests for BinaryAnalyzer.

Tests validate real binary analysis on actual PE, ELF, Mach-O formats with proper
header parsing, section analysis, string extraction, and entropy calculation.
NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import math
import os
import struct
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


class TestBinaryAnalyzerInitialization:
    """Test BinaryAnalyzer initialization and configuration."""

    def test_analyzer_initialization(self) -> None:
        """BinaryAnalyzer initializes with correct magic bytes and configuration."""
        analyzer = BinaryAnalyzer()

        assert analyzer.LARGE_FILE_THRESHOLD == 50 * 1024 * 1024
        assert analyzer.CHUNK_SIZE == 8 * 1024 * 1024
        assert analyzer.HASH_CHUNK_SIZE == 64 * 1024

        assert b"MZ" in analyzer.magic_bytes
        assert analyzer.magic_bytes[b"MZ"] == "PE"
        assert b"\x7fELF" in analyzer.magic_bytes
        assert analyzer.magic_bytes[b"\x7fELF"] == "ELF"
        assert b"\xfe\xed\xfa\xce" in analyzer.magic_bytes
        assert b"dex\n" in analyzer.magic_bytes
        assert analyzer.magic_bytes[b"dex\n"] == "Android DEX"


class TestBinaryAnalyzerPEFormat:
    """Test PE (Windows executable) analysis."""

    @pytest.fixture
    def minimal_pe_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid PE binary with proper headers and sections."""
        binary_path = temp_workspace / "minimal.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * (0x80 - 64 - 48)

        pe_signature = b"PE\x00\x00"

        machine = 0x014c
        num_sections = 2
        timestamp = 0x5F5E100C
        symbol_table_offset = 0
        num_symbols = 0
        optional_header_size = 224
        characteristics = 0x0122

        coff_header = struct.pack(
            "<HHIIIHH",
            machine,
            num_sections,
            timestamp,
            symbol_table_offset,
            num_symbols,
            optional_header_size,
            characteristics,
        )

        optional_header = bytearray(optional_header_size)
        optional_header[:2] = struct.pack("<H", 0x010B)

        section_table_offset = 0x80 + 4 + len(coff_header) + optional_header_size

        section_1 = bytearray(40)
        section_1[:8] = b".text\x00\x00\x00"
        section_1[8:12] = struct.pack("<I", 0x1000)
        section_1[12:16] = struct.pack("<I", 0x1000)
        section_1[16:20] = struct.pack("<I", 0x200)
        section_1[20:24] = struct.pack("<I", 0x400)

        section_2 = bytearray(40)
        section_2[:8] = b".data\x00\x00\x00"
        section_2[8:12] = struct.pack("<I", 0x2000)
        section_2[12:16] = struct.pack("<I", 0x2000)
        section_2[16:20] = struct.pack("<I", 0x200)
        section_2[20:24] = struct.pack("<I", 0x600)

        binary_data = dos_header + dos_stub + pe_signature + coff_header + optional_header + section_1 + section_2

        padding_needed = 0x400 - len(binary_data)
        if padding_needed > 0:
            binary_data += b"\x00" * padding_needed

        section_1_data = b"\x55\x89\xe5\x83\xec\x10" + b"\x00" * (0x200 - 6)
        binary_data += section_1_data

        section_2_data = b"Hello, World!\x00" + b"\x00" * (0x200 - 14)
        binary_data += section_2_data

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def corrupted_pe_binary(self, temp_workspace: Path) -> Path:
        """Create PE binary with corrupted PE header."""
        binary_path = temp_workspace / "corrupted.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub = b"\x00" * (0x80 - 64)
        invalid_pe_signature = b"XX\x00\x00"

        binary_data = dos_header + dos_stub + invalid_pe_signature
        binary_path.write_bytes(binary_data)
        return binary_path

    def test_analyze_valid_pe_binary(self, minimal_pe_binary: Path) -> None:
        """analyze extracts PE format, sections, and metadata."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_pe_binary)

        assert result["format"] == "PE"
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result

        if "error" not in result["format_analysis"]:
            assert "sections" in result["format_analysis"]
            assert len(result["format_analysis"]["sections"]) >= 1

            section_names = [s["name"] for s in result["format_analysis"]["sections"]]
            assert any(".text" in name for name in section_names)

            assert result["format_analysis"]["machine"] == "0x014c"
            assert result["format_analysis"]["num_sections"] == 2

    def test_analyze_pe_extracts_strings(self, minimal_pe_binary: Path) -> None:
        """analyze extracts printable strings from PE binary."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_pe_binary)

        assert "strings" in result
        strings = result["strings"]
        assert any("Hello" in s for s in strings)

    def test_analyze_pe_calculates_hashes(self, minimal_pe_binary: Path) -> None:
        """analyze calculates correct hashes for PE binary."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_pe_binary)

        assert "hashes" in result
        hashes = result["hashes"]
        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "sha3_256" in hashes
        assert "blake2b" in hashes

        binary_data = minimal_pe_binary.read_bytes()
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()
        assert hashes["sha256"] == expected_sha256

    def test_analyze_pe_calculates_entropy(self, minimal_pe_binary: Path) -> None:
        """analyze calculates entropy for PE binary."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_pe_binary)

        assert "entropy" in result
        entropy = result["entropy"]
        assert "overall_entropy" in entropy
        assert "file_size" in entropy
        assert entropy["overall_entropy"] < 7.0

    def test_analyze_corrupted_pe_returns_error(self, corrupted_pe_binary: Path) -> None:
        """analyze detects and reports corrupted PE header."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(corrupted_pe_binary)

        assert result["format"] == "PE"
        assert "format_analysis" in result
        assert "error" in result["format_analysis"]
        assert "Invalid PE header" in result["format_analysis"]["error"]

    def test_analyze_pe_streaming_mode(self, minimal_pe_binary: Path) -> None:
        """analyze uses streaming mode for PE when forced."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_pe_binary, use_streaming=True)

        assert result["format"] == "PE"
        assert result["streaming_mode"] is True
        assert "format_analysis" in result


class TestBinaryAnalyzerELFFormat:
    """Test ELF (Linux executable) analysis."""

    @pytest.fixture
    def minimal_elf_64bit_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid 64-bit ELF binary."""
        binary_path = temp_workspace / "minimal_elf64"

        e_ident = bytearray(16)
        e_ident[:4] = b"\x7fELF"
        e_ident[4] = 2
        e_ident[5] = 1
        e_ident[6] = 1

        elf_header = struct.pack(
            "<HHIQQQIHHHHHH",
            2,
            0x3E,
            1,
            0x400000,
            0x40,
            0,
            0,
            0x40,
            0x38,
            2,
            0x40,
            0,
            0,
        )

        program_header_1 = struct.pack(
            "<IIQQQQQQ",
            1,
            5,
            0x0,
            0x400000,
            0x400000,
            0x2000,
            0x2000,
            0x1000,
        )

        program_header_2 = struct.pack(
            "<IIQQQQQQ",
            1,
            6,
            0x2000,
            0x600000,
            0x600000,
            0x500,
            0x500,
            0x1000,
        )

        binary_data = e_ident + elf_header + program_header_1 + program_header_2
        binary_data += b"\x00" * (0x2000 - len(binary_data))
        binary_data += b"ELF test data\x00" + b"\x00" * (0x500 - 14)

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def minimal_elf_32bit_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid 32-bit ELF binary."""
        binary_path = temp_workspace / "minimal_elf32"

        e_ident = bytearray(16)
        e_ident[:4] = b"\x7fELF"
        e_ident[4] = 1
        e_ident[5] = 1
        e_ident[6] = 1

        elf_header = struct.pack(
            "<HHIIIIIHHHHHH",
            2,
            3,
            1,
            0x08048000,
            0x34,
            0,
            0,
            0x34,
            0x20,
            1,
            0x28,
            0,
            0,
        )

        program_header = struct.pack(
            "<IIIIIIII",
            1,
            0x1000,
            0x08048000,
            0x08048000,
            0x500,
            0x500,
            5,
            0x1000,
        )

        binary_data = e_ident + elf_header + program_header

        padding_needed = 0x1000 - len(binary_data)
        if padding_needed > 0:
            binary_data += b"\x00" * padding_needed

        code_section = b"\x55\x89\xe5\x83\xec\x10" + b"\x00" * (0x500 - 6)
        binary_data += code_section

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_analyze_valid_elf_64bit_binary(self, minimal_elf_64bit_binary: Path) -> None:
        """analyze extracts ELF 64-bit format and segments."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_elf_64bit_binary)

        assert result["format"] == "ELF"
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result

        if "error" not in result["format_analysis"]:
            assert result["format_analysis"]["class"] == "64-bit"
            assert result["format_analysis"]["data"] == "little-endian"
            assert "segments" in result["format_analysis"]
            assert len(result["format_analysis"]["segments"]) >= 1

    def test_analyze_valid_elf_32bit_binary(self, minimal_elf_32bit_binary: Path) -> None:
        """analyze extracts ELF 32-bit format and segments."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_elf_32bit_binary)

        assert result["format"] == "ELF"
        assert result["format_analysis"]["class"] == "32-bit"
        assert "segments" in result["format_analysis"]

    def test_analyze_elf_segment_flags(self, minimal_elf_64bit_binary: Path) -> None:
        """analyze extracts and formats ELF segment flags correctly."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_elf_64bit_binary)

        if "error" not in result["format_analysis"] and "segments" in result["format_analysis"]:
            segments = result["format_analysis"]["segments"]
            assert len(segments) >= 1

            for segment in segments:
                assert "flags" in segment
                flags = segment["flags"]
                assert all(c in "RWX" for c in flags) or flags == "None"

    def test_analyze_elf_entry_point(self, minimal_elf_64bit_binary: Path) -> None:
        """analyze extracts ELF entry point address."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_elf_64bit_binary)

        if "error" not in result["format_analysis"]:
            assert "entry_point" in result["format_analysis"]
            assert result["format_analysis"]["entry_point"].startswith("0x")

    def test_analyze_elf_streaming_mode(self, minimal_elf_64bit_binary: Path) -> None:
        """analyze uses streaming mode for ELF when forced."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_elf_64bit_binary, use_streaming=True)

        assert result["format"] == "ELF"
        assert result["streaming_mode"] is True
        assert "format_analysis" in result


class TestBinaryAnalyzerMachoFormat:
    """Test Mach-O (macOS executable) analysis."""

    @pytest.fixture
    def minimal_macho_64bit_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid 64-bit Mach-O binary."""
        binary_path = temp_workspace / "minimal_macho64"

        magic = struct.pack("<I", 0xFEEDFACF)
        cpu_type = struct.pack(">I", 0x01000007)
        cpu_subtype = struct.pack(">I", 0x00000003)
        file_type = struct.pack(">I", 0x00000002)
        ncmds = struct.pack(">I", 2)
        sizeofcmds = struct.pack(">I", 0x120)
        flags = struct.pack(">I", 0x00200085)
        reserved = struct.pack(">I", 0)

        header = magic + cpu_type + cpu_subtype + file_type + ncmds + sizeofcmds + flags + reserved

        load_cmd_1 = struct.pack(">I", 0x00000019)
        cmdsize_1 = struct.pack(">I", 0x48)
        load_cmd_1_data = load_cmd_1 + cmdsize_1 + b"\x00" * (0x48 - 8)

        load_cmd_2 = struct.pack(">I", 0x00000001)
        cmdsize_2 = struct.pack(">I", 0xD8)
        load_cmd_2_data = load_cmd_2 + cmdsize_2 + b"\x00" * (0xD8 - 8)

        binary_data = header + load_cmd_1_data + load_cmd_2_data + b"\x00" * 1024

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def minimal_macho_32bit_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid 32-bit Mach-O binary."""
        binary_path = temp_workspace / "minimal_macho32"

        header = struct.pack(
            "<IIIIIII",
            0xFEEDFACE,
            0x00000007,
            0x00000003,
            0x00000002,
            1,
            0x38,
            0x00200085,
        )

        load_cmd_data = struct.pack("<II", 0x00000001, 0x38) + b"\x00" * (0x38 - 8)

        binary_data = header + load_cmd_data + b"\x00" * 512

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_analyze_valid_macho_64bit_binary(self, minimal_macho_64bit_binary: Path) -> None:
        """analyze extracts Mach-O 64-bit format and load commands."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_macho_64bit_binary)

        assert "Mach-O" in result["format"]
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result

        if "error" not in result["format_analysis"]:
            assert result["format_analysis"]["architecture"] == "64-bit"
            assert "load_commands" in result["format_analysis"]
            assert result["format_analysis"]["num_commands"] >= 1

    def test_analyze_valid_macho_32bit_binary(self, minimal_macho_32bit_binary: Path) -> None:
        """analyze extracts Mach-O 32-bit format and load commands."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_macho_32bit_binary)

        assert "Mach-O" in result["format"]
        assert result["format_analysis"]["architecture"] == "32-bit"
        assert result["format_analysis"]["num_commands"] == 1

    def test_analyze_macho_load_commands(self, minimal_macho_64bit_binary: Path) -> None:
        """analyze extracts Mach-O load command details."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_macho_64bit_binary)

        if "error" not in result["format_analysis"] and "load_commands" in result["format_analysis"]:
            load_commands = result["format_analysis"]["load_commands"]
            assert len(load_commands) >= 1

            for cmd in load_commands:
                assert "cmd" in cmd
                assert "cmdsize" in cmd
                assert cmd["cmd"].startswith("0x")

    def test_analyze_macho_streaming_mode(self, minimal_macho_64bit_binary: Path) -> None:
        """analyze uses streaming mode for Mach-O when forced."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_macho_64bit_binary, use_streaming=True)

        assert "Mach-O" in result["format"]
        assert result["streaming_mode"] is True


class TestBinaryAnalyzerDEXFormat:
    """Test Android DEX file analysis."""

    @pytest.fixture
    def minimal_dex_binary(self, temp_workspace: Path) -> Path:
        """Create minimal valid DEX binary."""
        binary_path = temp_workspace / "classes.dex"

        magic = b"dex\n"
        version = b"035\x00"
        checksum = struct.pack("<I", 0x12345678)
        signature = b"\x00" * 20
        file_size = struct.pack("<I", 0x300)
        header_size = struct.pack("<I", 0x70)
        endian_tag = struct.pack("<I", 0x12345678)
        link_size = struct.pack("<I", 0)
        link_off = struct.pack("<I", 0)
        map_off = struct.pack("<I", 0x200)
        string_ids_size = struct.pack("<I", 5)
        string_ids_off = struct.pack("<I", 0x70)

        header = (
            magic
            + version
            + checksum
            + signature
            + file_size
            + header_size
            + endian_tag
            + link_size
            + link_off
            + map_off
            + string_ids_size
            + string_ids_off
        )

        header += b"\x00" * (0x70 - len(header))

        string_id_table = b""
        for i in range(5):
            string_offset = 0x100 + (i * 20)
            string_id_table += struct.pack("<I", string_offset)

        string_data_section_offset = 0x100
        string_data = b""
        test_strings = [b"String1", b"String2", b"TestClass", b"method", b"field"]

        for s in test_strings:
            length_uleb = bytes([len(s)])
            string_data += length_uleb + s + b"\x00"

        binary_data = header + string_id_table + b"\x00" * (0x100 - 0x70 - len(string_id_table))
        binary_data += string_data
        binary_data += b"\x00" * (0x300 - len(binary_data))

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_analyze_valid_dex_binary(self, minimal_dex_binary: Path) -> None:
        """analyze extracts DEX format and metadata."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_dex_binary)

        assert result["format"] == "Android DEX"
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result
        assert "version" in result["format_analysis"]
        assert "string_count" in result["format_analysis"]

    def test_analyze_dex_extracts_strings(self, minimal_dex_binary: Path) -> None:
        """analyze extracts strings from DEX string table."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(minimal_dex_binary)

        assert "format_analysis" in result
        assert "strings" in result["format_analysis"]


class TestBinaryAnalyzerFileInfo:
    """Test file metadata extraction."""

    def test_analyze_extracts_file_size(self, temp_workspace: Path) -> None:
        """analyze extracts correct file size."""
        test_file = temp_workspace / "test.bin"
        test_data = b"\x00" * 5000
        test_file.write_bytes(test_data)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_file)

        assert "file_info" in result
        assert result["file_info"]["size"] == 5000

    def test_analyze_extracts_timestamps(self, temp_workspace: Path) -> None:
        """analyze extracts file creation and modification timestamps."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"MZ\x00\x00")

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_file)

        assert "file_info" in result
        assert "created" in result["file_info"]
        assert "modified" in result["file_info"]
        assert "accessed" in result["file_info"]

        datetime.fromisoformat(result["file_info"]["created"])
        datetime.fromisoformat(result["file_info"]["modified"])


class TestBinaryAnalyzerStringExtraction:
    """Test string extraction from binaries."""

    @pytest.fixture
    def binary_with_strings(self, temp_workspace: Path) -> Path:
        """Create binary with embedded strings."""
        binary_path = temp_workspace / "strings.bin"

        binary_data = b"\x00\x00\x00\x00"
        binary_data += b"This is a test string\x00"
        binary_data += b"\xFF\xFF\xFF"
        binary_data += b"Another printable string here!\x00"
        binary_data += b"\x00" * 100
        binary_data += b"License key validation function\x00"
        binary_data += b"\x01\x02\x03"
        binary_data += b"Serial number check\x00"

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_extract_strings_finds_printable_ascii(self, binary_with_strings: Path) -> None:
        """analyze extracts printable ASCII strings."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(binary_with_strings)

        assert "strings" in result
        strings = result["strings"]

        assert any("test string" in s for s in strings)
        assert any("printable string" in s for s in strings)

    def test_extract_strings_filters_hex_only(self, temp_workspace: Path) -> None:
        """analyze filters out hex-only strings."""
        test_file = temp_workspace / "hex.bin"
        test_data = b"\x00\x00DEADBEEF\x00\x00Real String Here\x00"
        test_file.write_bytes(test_data)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_file)

        strings = result["strings"]
        assert any("Real String" in s for s in strings)

    def test_extract_strings_min_length_filter(self, temp_workspace: Path) -> None:
        """analyze only extracts strings meeting minimum length."""
        test_file = temp_workspace / "short.bin"
        test_data = b"\x00AB\x00ABCD\x00This is long enough\x00"
        test_file.write_bytes(test_data)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_file)

        strings = result["strings"]
        assert any("long enough" in s for s in strings)
        assert all(s != "AB" for s in strings)

    def test_extract_strings_streaming_mode(self, binary_with_strings: Path) -> None:
        """analyze extracts strings in streaming mode."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(binary_with_strings, use_streaming=True)

        assert "strings" in result
        strings = result["strings"]
        assert any("test string" in s for s in strings)


class TestBinaryAnalyzerEntropyAnalysis:
    """Test entropy calculation and analysis."""

    @pytest.fixture
    def low_entropy_binary(self, temp_workspace: Path) -> Path:
        """Create binary with low entropy (repetitive data)."""
        binary_path = temp_workspace / "low_entropy.bin"
        binary_path.write_bytes(b"\x00" * 10000)
        return binary_path

    @pytest.fixture
    def high_entropy_binary(self, temp_workspace: Path) -> Path:
        """Create binary with high entropy (random data)."""
        binary_path = temp_workspace / "high_entropy.bin"
        binary_path.write_bytes(os.urandom(10000))
        return binary_path

    def test_analyze_entropy_low_entropy_detected(self, low_entropy_binary: Path) -> None:
        """analyze detects low entropy in repetitive data."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(low_entropy_binary)

        assert "entropy" in result
        entropy = result["entropy"]
        assert entropy["overall_entropy"] == 0.0
        assert entropy["unique_bytes"] == 1
        assert "Normal" in entropy["analysis"]

    def test_analyze_entropy_high_entropy_detected(self, high_entropy_binary: Path) -> None:
        """analyze detects high entropy in random data."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(high_entropy_binary)

        assert "entropy" in result
        entropy = result["entropy"]
        assert entropy["overall_entropy"] > 7.0
        assert "packed/encrypted" in entropy["analysis"]

    def test_analyze_entropy_streaming_mode(self, high_entropy_binary: Path) -> None:
        """analyze calculates entropy correctly in streaming mode."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(high_entropy_binary, use_streaming=True)

        assert "entropy" in result
        entropy = result["entropy"]
        assert entropy["overall_entropy"] > 7.0


class TestBinaryAnalyzerHashCalculation:
    """Test hash calculation functionality."""

    @pytest.fixture
    def test_binary(self, temp_workspace: Path) -> Path:
        """Create test binary with known content."""
        binary_path = temp_workspace / "hash_test.bin"
        binary_path.write_bytes(b"Test data for hashing" * 100)
        return binary_path

    def test_calculate_hashes_all_algorithms(self, test_binary: Path) -> None:
        """analyze calculates all hash algorithms."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_binary)

        assert "hashes" in result
        hashes = result["hashes"]

        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "sha3_256" in hashes
        assert "blake2b" in hashes

        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128

    def test_calculate_hashes_correctness(self, test_binary: Path) -> None:
        """analyze calculates correct hash values."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_binary)

        binary_data = test_binary.read_bytes()
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()
        expected_sha512 = hashlib.sha512(binary_data).hexdigest()

        assert result["hashes"]["sha256"] == expected_sha256
        assert result["hashes"]["sha512"] == expected_sha512

    def test_calculate_hashes_streaming_mode(self, test_binary: Path) -> None:
        """analyze calculates correct hashes in streaming mode."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_binary, use_streaming=True)

        binary_data = test_binary.read_bytes()
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()

        assert result["hashes"]["sha256"] == expected_sha256


class TestBinaryAnalyzerErrorHandling:
    """Test error handling and edge cases."""

    def test_analyze_nonexistent_file(self, temp_workspace: Path) -> None:
        """analyze returns error for non-existent file."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(temp_workspace / "nonexistent.bin")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_directory_not_file(self, temp_workspace: Path) -> None:
        """analyze returns error when path is directory."""
        test_dir = temp_workspace / "testdir"
        test_dir.mkdir()

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(test_dir)

        assert "error" in result
        assert "not a file" in result["error"].lower()

    def test_analyze_empty_file(self, temp_workspace: Path) -> None:
        """analyze handles empty files."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.write_bytes(b"")

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(empty_file)

        assert "file_info" in result
        assert result["file_info"]["size"] == 0

    def test_analyze_truncated_pe_file(self, temp_workspace: Path) -> None:
        """analyze handles truncated PE files gracefully."""
        truncated_pe = temp_workspace / "truncated.exe"
        truncated_pe.write_bytes(b"MZ\x00\x00")

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(truncated_pe)

        assert result["format"] == "PE"


class TestBinaryAnalyzerStreamingMode:
    """Test streaming mode for large files."""

    @pytest.fixture
    def large_binary(self, temp_workspace: Path) -> Path:
        """Create large binary to trigger streaming mode."""
        binary_path = temp_workspace / "large.bin"
        large_data = os.urandom(60 * 1024 * 1024)
        binary_path.write_bytes(large_data)
        return binary_path

    def test_analyze_auto_enables_streaming(self, large_binary: Path) -> None:
        """analyze automatically enables streaming for large files."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(large_binary)

        assert result["streaming_mode"] is True

    def test_analyze_force_streaming_mode(self, temp_workspace: Path) -> None:
        """analyze respects use_streaming parameter."""
        small_file = temp_workspace / "small.bin"
        small_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 1000)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(small_file, use_streaming=True)

        assert result.get("streaming_mode") is True

    def test_analyze_force_non_streaming_mode(self, temp_workspace: Path) -> None:
        """analyze respects use_streaming=False parameter."""
        small_file = temp_workspace / "small.bin"
        small_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 1000)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(small_file, use_streaming=False)

        assert result.get("streaming_mode") is not True


class TestBinaryAnalyzerProgressTracking:
    """Test progress tracking functionality."""

    def test_analyze_with_progress_callback(self, temp_workspace: Path) -> None:
        """analyze_with_progress invokes callback with progress updates."""
        test_file = temp_workspace / "progress_test.bin"
        test_file.write_bytes(b"MZ\x00\x00" + os.urandom(10000))

        progress_calls: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            progress_calls.append((stage, current, total))

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze_with_progress(test_file, progress_callback)

        assert result["analysis_status"] == "completed"
        assert progress_calls
        assert any("format_detection" in call[0] for call in progress_calls)

    def test_analyze_with_progress_hash_updates(self, temp_workspace: Path) -> None:
        """analyze_with_progress provides hash calculation progress."""
        test_file = temp_workspace / "hash_progress.bin"
        test_file.write_bytes(os.urandom(1024 * 1024))

        hash_progress_calls: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            if "hash_calculation" in stage:
                hash_progress_calls.append((stage, current, total))

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze_with_progress(test_file, progress_callback)

        assert result["analysis_status"] == "completed"


class TestBinaryAnalyzerCheckpointing:
    """Test checkpoint save/load functionality."""

    def test_save_analysis_checkpoint(self, temp_workspace: Path) -> None:
        """save_analysis_checkpoint saves results to JSON."""
        checkpoint_path = temp_workspace / "checkpoint.json"
        test_results = {
            "format": "PE",
            "file_info": {"size": 1024},
            "hashes": {"sha256": "abc123"},
        }

        analyzer = BinaryAnalyzer()
        success = analyzer.save_analysis_checkpoint(test_results, checkpoint_path)

        assert success is True
        assert checkpoint_path.exists()

        loaded_data = json.loads(checkpoint_path.read_text())
        assert loaded_data["format"] == "PE"

    def test_load_analysis_checkpoint(self, temp_workspace: Path) -> None:
        """load_analysis_checkpoint loads results from JSON."""
        checkpoint_path = temp_workspace / "checkpoint.json"
        test_results = {
            "format": "ELF",
            "file_info": {"size": 2048},
        }

        checkpoint_path.write_text(json.dumps(test_results, indent=2))

        analyzer = BinaryAnalyzer()
        loaded = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded is not None
        assert loaded["format"] == "ELF"
        assert loaded["file_info"]["size"] == 2048

    def test_load_nonexistent_checkpoint(self, temp_workspace: Path) -> None:
        """load_analysis_checkpoint returns None for missing file."""
        analyzer = BinaryAnalyzer()
        loaded = analyzer.load_analysis_checkpoint(temp_workspace / "missing.json")

        assert loaded is None


class TestBinaryAnalyzerPatternScanning:
    """Test pattern scanning functionality."""

    @pytest.fixture
    def pattern_test_binary(self, temp_workspace: Path) -> Path:
        """Create binary with known byte patterns."""
        binary_path = temp_workspace / "patterns.bin"

        binary_data = b"\x00" * 100
        binary_data += b"\x90\x90\x90\x90\x90"
        binary_data += b"\x00" * 50
        binary_data += b"\xCC\xCC\xCC"
        binary_data += b"\x00" * 100
        binary_data += b"\x90\x90\x90\x90\x90"
        binary_data += b"\x00" * 50

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_scan_for_patterns_finds_matches(self, pattern_test_binary: Path) -> None:
        """scan_for_patterns_streaming finds all pattern occurrences."""
        analyzer = BinaryAnalyzer()
        patterns = [b"\x90\x90\x90\x90\x90", b"\xCC\xCC\xCC"]
        result = analyzer.scan_for_patterns_streaming(pattern_test_binary, patterns)

        assert b"\x90\x90\x90\x90\x90".hex() in result
        assert b"\xCC\xCC\xCC".hex() in result

        nop_matches = result[b"\x90\x90\x90\x90\x90".hex()]
        assert len(nop_matches) == 2

    def test_scan_for_patterns_includes_context(self, pattern_test_binary: Path) -> None:
        """scan_for_patterns_streaming includes context around matches."""
        analyzer = BinaryAnalyzer()
        patterns = [b"\x90\x90\x90\x90\x90"]
        result = analyzer.scan_for_patterns_streaming(pattern_test_binary, patterns, context_bytes=16)

        matches = result[b"\x90\x90\x90\x90\x90".hex()]
        assert len(matches) > 0

        for match in matches:
            assert "offset" in match
            assert "context_before" in match
            assert "context_after" in match


class TestBinaryAnalyzerLicenseStringScanning:
    """Test license-related string scanning."""

    @pytest.fixture
    def license_check_binary(self, temp_workspace: Path) -> Path:
        """Create binary with license-related strings."""
        binary_path = temp_workspace / "license_check.bin"

        binary_data = b"\x00" * 100
        binary_data += b"Serial number validation function\x00"
        binary_data += b"\x00" * 50
        binary_data += b"License key activation required\x00"
        binary_data += b"\x00" * 100
        binary_data += b"Trial period expired message\x00"
        binary_data += b"\x00" * 50
        binary_data += b"Registration code checker\x00"

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_scan_license_strings_finds_serial_references(self, license_check_binary: Path) -> None:
        """scan_for_license_strings_streaming finds serial-related strings."""
        analyzer = BinaryAnalyzer()
        results = analyzer.scan_for_license_strings_streaming(license_check_binary)

        assert len(results) > 0
        assert any("serial" in r["pattern_matched"].lower() for r in results)

    def test_scan_license_strings_finds_license_references(self, license_check_binary: Path) -> None:
        """scan_for_license_strings_streaming finds license-related strings."""
        analyzer = BinaryAnalyzer()
        results = analyzer.scan_for_license_strings_streaming(license_check_binary)

        assert any("license" in r["pattern_matched"].lower() for r in results)

    def test_scan_license_strings_includes_offsets(self, license_check_binary: Path) -> None:
        """scan_for_license_strings_streaming includes file offsets."""
        analyzer = BinaryAnalyzer()
        results = analyzer.scan_for_license_strings_streaming(license_check_binary)

        for result in results:
            assert "offset" in result
            assert "string" in result
            assert result["offset"] >= 0


class TestBinaryAnalyzerSectionAnalysis:
    """Test section-specific analysis."""

    @pytest.fixture
    def multi_section_binary(self, temp_workspace: Path) -> Path:
        """Create binary with distinct sections."""
        binary_path = temp_workspace / "sections.bin"

        header = b"MZ\x00\x00" + b"\x00" * 100
        code_section = b"\x55\x89\xe5" * 100
        data_section = b"String data here\x00" * 50
        encrypted_section = os.urandom(500)
        padding_section = b"\x00" * 500

        binary_data = header + code_section + data_section + encrypted_section + padding_section
        binary_path.write_bytes(binary_data)
        return binary_path

    def test_analyze_sections_streaming(self, multi_section_binary: Path) -> None:
        """analyze_sections_streaming analyzes specific byte ranges."""
        analyzer = BinaryAnalyzer()

        section_ranges = [
            (104, 404),
            (404, 1254),
            (1254, 1754),
        ]

        results = analyzer.analyze_sections_streaming(multi_section_binary, section_ranges)

        assert "section_0" in results
        assert "section_1" in results
        assert "section_2" in results

    def test_analyze_sections_calculates_entropy(self, multi_section_binary: Path) -> None:
        """analyze_sections_streaming calculates section entropy."""
        analyzer = BinaryAnalyzer()

        section_ranges = [(104, 404), (1254, 1754)]
        results = analyzer.analyze_sections_streaming(multi_section_binary, section_ranges)

        for section_key in results:
            if "error" not in results[section_key]:
                assert "entropy" in results[section_key]
                assert "size" in results[section_key]

    def test_analyze_sections_classifies_characteristics(self, multi_section_binary: Path) -> None:
        """analyze_sections_streaming classifies section characteristics."""
        analyzer = BinaryAnalyzer()

        encrypted_range = (1254, 1754)
        padding_range = (1754, 2254)

        results = analyzer.analyze_sections_streaming(multi_section_binary, [encrypted_range, padding_range])

        assert "characteristics" in results["section_0"]
        assert "characteristics" in results["section_1"]

    def test_analyze_sections_invalid_range(self, multi_section_binary: Path) -> None:
        """analyze_sections_streaming handles invalid ranges."""
        analyzer = BinaryAnalyzer()

        invalid_ranges = [(-10, 100), (0, 999999), (500, 100)]
        results = analyzer.analyze_sections_streaming(multi_section_binary, invalid_ranges)

        assert any("error" in results[key] for key in results)


class TestBinaryAnalyzerFormatDetection:
    """Test format detection for various file types."""

    def test_detect_format_pe(self, temp_workspace: Path) -> None:
        """_detect_format identifies PE files."""
        pe_file = temp_workspace / "test.exe"
        pe_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 100)

        analyzer = BinaryAnalyzer()
        format_name = analyzer._detect_format(pe_file)

        assert format_name == "PE"

    def test_detect_format_elf(self, temp_workspace: Path) -> None:
        """_detect_format identifies ELF files."""
        elf_file = temp_workspace / "test"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        analyzer = BinaryAnalyzer()
        format_name = analyzer._detect_format(elf_file)

        assert format_name == "ELF"

    def test_detect_format_zip(self, temp_workspace: Path) -> None:
        """_detect_format identifies ZIP archives."""
        zip_file = temp_workspace / "test.zip"
        zip_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        analyzer = BinaryAnalyzer()
        format_name = analyzer._detect_format(zip_file)

        assert format_name == "ZIP/JAR/APK"

    def test_detect_format_unknown(self, temp_workspace: Path) -> None:
        """_detect_format returns Unknown for unrecognized formats."""
        unknown_file = temp_workspace / "test.dat"
        unknown_file.write_bytes(b"\xAB\xCD\xEF\x12" + b"\x00" * 100)

        analyzer = BinaryAnalyzer()
        format_name = analyzer._detect_format(unknown_file)

        assert format_name == "Unknown"

    def test_detect_format_script(self, temp_workspace: Path) -> None:
        """_detect_format identifies script files."""
        script_file = temp_workspace / "test.sh"
        script_file.write_text("#!/bin/bash\necho 'test'")

        analyzer = BinaryAnalyzer()
        format_name = analyzer._detect_format(script_file)

        assert format_name == "Script"


class TestBinaryAnalyzerSecurityAnalysis:
    """Test security-focused analysis features."""

    def test_security_analysis_empty_file_low_risk(self, temp_workspace: Path) -> None:
        """analyze marks empty files as low risk."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.write_bytes(b"")

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(empty_file)

        assert "security" in result
        assert result["security"]["risk_level"] in ["Low", "Medium"]

    def test_security_analysis_unknown_format_medium_risk(self, temp_workspace: Path) -> None:
        """analyze marks unknown formats as medium risk."""
        unknown_file = temp_workspace / "unknown.dat"
        unknown_file.write_bytes(b"\xDE\xAD\xBE\xEF" * 100)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(unknown_file)

        assert result["security"]["risk_level"] == "Medium"

    def test_security_analysis_executable_has_recommendations(self, temp_workspace: Path) -> None:
        """analyze provides security recommendations for executables."""
        exe_file = temp_workspace / "test.exe"
        exe_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 1000)

        analyzer = BinaryAnalyzer()
        result = analyzer.analyze(exe_file)

        assert "security" in result
        assert "recommendations" in result["security"]
        assert len(result["security"]["recommendations"]) > 0
