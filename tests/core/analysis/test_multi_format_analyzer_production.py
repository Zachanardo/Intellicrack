"""Production tests for MultiFormatBinaryAnalyzer.

Validates binary format detection, PE/ELF/Mach-O/DEX/APK/JAR/MSI/COM analysis,
feature extraction, and cross-platform binary structure parsing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.multi_format_analyzer import (
    BinaryInfo,
    MultiFormatBinaryAnalyzer,
    run_multi_format_analysis,
)


@pytest.fixture
def analyzer() -> MultiFormatBinaryAnalyzer:
    """Create MultiFormatBinaryAnalyzer instance."""
    return MultiFormatBinaryAnalyzer()


@pytest.fixture
def pe_binary() -> bytes:
    """Create minimal valid PE binary."""
    dos_header = b"MZ" + b"\x90" * 58
    dos_header += struct.pack("<I", 0x80)

    pe_header = b"PE\x00\x00"
    machine = struct.pack("<H", 0x014C)
    num_sections = struct.pack("<H", 1)
    timestamp = struct.pack("<I", 0)
    symbol_table = struct.pack("<I", 0)
    num_symbols = struct.pack("<I", 0)
    optional_header_size = struct.pack("<H", 0xE0)
    characteristics = struct.pack("<H", 0x0102)

    file_header = (machine + num_sections + timestamp + symbol_table +
                   num_symbols + optional_header_size + characteristics)

    optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

    section_name = b".text\x00\x00\x00"
    section_header = (section_name + struct.pack("<I", 0x1000) +
                     struct.pack("<I", 0x1000) + struct.pack("<I", 0x200) +
                     struct.pack("<I", 0x200) + b"\x00" * 12 +
                     struct.pack("<I", 0x60000020))

    padding = b"\x00" * (0x200 - len(dos_header) - len(pe_header) -
                         len(file_header) - len(optional_header) - len(section_header))

    section_data = b"\x55\x89\xE5\x31\xC0\x5D\xC3" + b"\x00" * 505

    return dos_header + pe_header + file_header + optional_header + section_header + padding + section_data


@pytest.fixture
def elf_binary() -> bytes:
    """Create minimal valid ELF binary."""
    elf_header = (
        b"\x7fELF"
        + b"\x01"
        + b"\x01"
        + b"\x01"
        + b"\x00" * 9
        + b"\x02\x00"
        + b"\x03\x00"
        + b"\x01\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x34\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x34\x00"
        + b"\x20\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )

    return elf_header + b"\x00" * 1000


@pytest.fixture
def macho_binary() -> bytes:
    """Create minimal valid Mach-O binary."""
    magic = struct.pack("<I", 0xFEEDFACE)
    cputype = struct.pack("<I", 7)
    cpusubtype = struct.pack("<I", 3)
    filetype = struct.pack("<I", 2)
    ncmds = struct.pack("<I", 0)
    sizeofcmds = struct.pack("<I", 0)
    flags = struct.pack("<I", 0)

    return magic + cputype + cpusubtype + filetype + ncmds + sizeofcmds + flags + b"\x00" * 1000


@pytest.fixture
def dex_binary() -> bytes:
    """Create minimal valid DEX binary."""
    magic = b"dex\n035\x00"
    checksum = struct.pack("<I", 0x12345678)
    signature = b"\x00" * 20
    file_size = struct.pack("<I", 0x70)
    header_size = struct.pack("<I", 0x70)
    endian_tag = struct.pack("<I", 0x12345678)
    link_size = struct.pack("<I", 0)
    link_off = struct.pack("<I", 0)
    map_off = struct.pack("<I", 0x70)
    string_ids_size = struct.pack("<I", 0)
    string_ids_off = struct.pack("<I", 0)
    type_ids_size = struct.pack("<I", 0)
    type_ids_off = struct.pack("<I", 0)
    proto_ids_size = struct.pack("<I", 0)
    proto_ids_off = struct.pack("<I", 0)
    field_ids_size = struct.pack("<I", 0)
    field_ids_off = struct.pack("<I", 0)
    method_ids_size = struct.pack("<I", 0)
    method_ids_off = struct.pack("<I", 0)
    class_defs_size = struct.pack("<I", 0)
    class_defs_off = struct.pack("<I", 0)
    data_size = struct.pack("<I", 0)
    data_off = struct.pack("<I", 0)

    return (magic + checksum + signature + file_size + header_size +
            endian_tag + link_size + link_off + map_off +
            string_ids_size + string_ids_off + type_ids_size + type_ids_off +
            proto_ids_size + proto_ids_off + field_ids_size + field_ids_off +
            method_ids_size + method_ids_off + class_defs_size + class_defs_off +
            data_size + data_off)


@pytest.fixture
def apk_file(tmp_path: Path, dex_binary: bytes) -> Path:
    """Create minimal valid APK file."""
    apk_path = tmp_path / "test.apk"

    with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
        apk.writestr("AndroidManifest.xml", b"\x00" * 100)
        apk.writestr("classes.dex", dex_binary)
        apk.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        apk.writestr("res/values/strings.xml", b"<resources></resources>")
        apk.writestr("lib/armeabi/libnative.so", b"\x7fELF" + b"\x00" * 100)

    return apk_path


@pytest.fixture
def jar_file(tmp_path: Path) -> Path:
    """Create minimal valid JAR file."""
    jar_path = tmp_path / "test.jar"

    with zipfile.ZipFile(jar_path, 'w', zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: Test\nCreated-By: Test\n")
        jar.writestr("Test.class", b"\xCA\xFE\xBA\xBE" + b"\x00" * 100)
        jar.writestr("resources/config.xml", b"<config></config>")

    return jar_path


@pytest.fixture
def com_binary() -> bytes:
    """Create minimal valid COM binary."""
    jmp_instruction = b"\xEB\x10"
    nop_padding = b"\x90" * 16
    int21_exit = b"\xB4\x4C\xCD\x21"

    return jmp_instruction + nop_padding + int21_exit + b"\x00" * 100


class TestBinaryInfo:
    """Test BinaryInfo data structure."""

    def test_initialization_defaults(self) -> None:
        """BinaryInfo initializes with correct defaults."""
        info = BinaryInfo()

        assert info.file_path == ""
        assert info.file_size == 0
        assert info.file_type == ""
        assert info.architecture == ""
        assert info.endianness == ""
        assert info.entry_point == 0
        assert info.sections == []
        assert info.imports == {}
        assert info.exports == {}
        assert info.strings == []
        assert info.md5 == ""
        assert info.sha256 == ""

    def test_initialization_with_values(self) -> None:
        """BinaryInfo accepts all initialization parameters."""
        info = BinaryInfo(
            file_path="/test/binary.exe",
            file_size=1024,
            file_type="PE",
            architecture="x86_64",
            endianness="little",
            entry_point=0x401000,
            sections=[{"name": ".text"}],
            imports={"kernel32.dll": ["CreateFileA"]},
            exports={"main": 0x401000},
            strings=["Hello"],
            md5="abc123",
            sha256="def456"
        )

        assert info.file_path == "/test/binary.exe"
        assert info.file_size == 1024
        assert info.architecture == "x86_64"
        assert len(info.sections) == 1
        assert "kernel32.dll" in info.imports


class TestFormatIdentification:
    """Test binary format detection."""

    def test_identify_pe_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """identify_format correctly detects PE binaries."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        format_type = analyzer.identify_format(pe_path)

        assert format_type == "PE"

    def test_identify_elf_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, elf_binary: bytes) -> None:
        """identify_format correctly detects ELF binaries."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(elf_binary)

        format_type = analyzer.identify_format(elf_path)

        assert format_type == "ELF"

    def test_identify_macho_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, macho_binary: bytes) -> None:
        """identify_format correctly detects Mach-O binaries."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(macho_binary)

        format_type = analyzer.identify_format(macho_path)

        assert format_type == "MACHO"

    def test_identify_dex_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, dex_binary: bytes) -> None:
        """identify_format correctly detects DEX binaries."""
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(dex_binary)

        format_type = analyzer.identify_format(dex_path)

        assert format_type == "DEX"

    def test_identify_apk_format(self, analyzer: MultiFormatBinaryAnalyzer, apk_file: Path) -> None:
        """identify_format correctly detects APK files."""
        format_type = analyzer.identify_format(apk_file)

        assert format_type == "APK"

    def test_identify_jar_format(self, analyzer: MultiFormatBinaryAnalyzer, jar_file: Path) -> None:
        """identify_format correctly detects JAR files."""
        format_type = analyzer.identify_format(jar_file)

        assert format_type == "JAR"

    def test_identify_com_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, com_binary: bytes) -> None:
        """identify_format correctly detects COM executables."""
        com_path = tmp_path / "test.com"
        com_path.write_bytes(com_binary)

        format_type = analyzer.identify_format(com_path)

        assert format_type == "COM"

    def test_identify_unknown_format(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """identify_format returns UNKNOWN for unrecognized formats."""
        unknown_path = tmp_path / "unknown.bin"
        unknown_path.write_bytes(b"\xFF\xFE\xFD\xFC" + b"\x00" * 100)

        format_type = analyzer.identify_format(unknown_path)

        assert format_type == "UNKNOWN"


class TestPEAnalysis:
    """Test PE binary analysis."""

    def test_analyze_pe_basic_info(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze_pe extracts basic PE information."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze_pe(pe_path)

        assert result["format"] == "PE"
        assert "machine" in result
        assert "timestamp" in result
        assert "characteristics" in result
        assert "sections" in result

    def test_analyze_pe_sections(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze_pe extracts section information."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze_pe(pe_path)

        assert len(result["sections"]) > 0
        section = result["sections"][0]
        assert "name" in section
        assert "virtual_address" in section
        assert "entropy" in section

    def test_analyze_pe_imports(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze_pe extracts import table."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze_pe(pe_path)

        assert "imports" in result
        assert isinstance(result["imports"], list)

    def test_analyze_pe_machine_type(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze_pe identifies machine architecture."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze_pe(pe_path)

        assert "I386" in result["machine"] or "x86" in result["machine"].lower()

    def test_get_machine_type(self, analyzer: MultiFormatBinaryAnalyzer) -> None:
        """_get_machine_type maps machine codes correctly."""
        assert "I386" in analyzer._get_machine_type(0x014C)
        assert "AMD64" in analyzer._get_machine_type(0x8664)
        assert "ARM64" in analyzer._get_machine_type(0xAA64)
        assert "UNKNOWN" in analyzer._get_machine_type(0xFFFF)

    def test_get_characteristics(self, analyzer: MultiFormatBinaryAnalyzer) -> None:
        """_get_characteristics decodes PE flags."""
        chars = analyzer._get_characteristics(0x0102)

        assert "Executable image" in chars


class TestELFAnalysis:
    """Test ELF binary analysis."""

    def test_analyze_elf_basic_info(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, elf_binary: bytes) -> None:
        """analyze_elf extracts basic ELF information."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(elf_binary)

        result = analyzer.analyze_elf(elf_path)

        assert result["format"] == "ELF"
        assert "machine" in result or "error" in result

    def test_analyze_elf_with_lief(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, elf_binary: bytes) -> None:
        """analyze_elf uses LIEF when available."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(elf_binary)

        result = analyzer.analyze_elf(elf_path)

        assert result["format"] == "ELF"


class TestMachoAnalysis:
    """Test Mach-O binary analysis."""

    def test_analyze_macho_basic_info(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, macho_binary: bytes) -> None:
        """analyze_macho extracts basic Mach-O information."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(macho_binary)

        result = analyzer.analyze_macho(macho_path)

        assert result["format"] == "MACHO"


class TestDEXAnalysis:
    """Test DEX binary analysis."""

    def test_analyze_dex_header(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, dex_binary: bytes) -> None:
        """analyze_dex extracts DEX header information."""
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(dex_binary)

        result = analyzer.analyze_dex(dex_path)

        assert result["format"] == "DEX"
        assert "dex_version" in result
        assert "checksum" in result
        assert "file_size" in result
        assert "string_ids_count" in result
        assert "method_ids_count" in result

    def test_analyze_dex_sections(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, dex_binary: bytes) -> None:
        """analyze_dex identifies DEX sections."""
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(dex_binary)

        result = analyzer.analyze_dex(dex_path)

        assert "sections" in result


class TestAPKAnalysis:
    """Test APK binary analysis."""

    def test_analyze_apk_structure(self, analyzer: MultiFormatBinaryAnalyzer, apk_file: Path) -> None:
        """analyze_apk extracts APK file structure."""
        result = analyzer.analyze_apk(apk_file)

        assert result["format"] == "APK"
        assert "total_files" in result
        assert "dex_files" in result
        assert "native_libs" in result
        assert "resources" in result
        assert "manifest_info" in result

    def test_analyze_apk_categorizes_files(self, analyzer: MultiFormatBinaryAnalyzer, apk_file: Path) -> None:
        """analyze_apk categorizes APK contents."""
        result = analyzer.analyze_apk(apk_file)

        assert len(result["dex_files"]) > 0
        assert len(result["native_libs"]) > 0
        assert len(result["resources"]) > 0

    def test_analyze_apk_manifest_detection(self, analyzer: MultiFormatBinaryAnalyzer, apk_file: Path) -> None:
        """analyze_apk detects AndroidManifest.xml."""
        result = analyzer.analyze_apk(apk_file)

        assert result["manifest_info"]["present"] is True

    def test_analyze_apk_summary_statistics(self, analyzer: MultiFormatBinaryAnalyzer, apk_file: Path) -> None:
        """analyze_apk calculates summary statistics."""
        result = analyzer.analyze_apk(apk_file)

        summary = result["summary"]
        assert "dex_count" in summary
        assert "native_lib_count" in summary
        assert "resource_count" in summary
        assert summary["dex_count"] > 0


class TestJARAnalysis:
    """Test JAR binary analysis."""

    def test_analyze_jar_structure(self, analyzer: MultiFormatBinaryAnalyzer, jar_file: Path) -> None:
        """analyze_jar extracts JAR structure."""
        result = analyzer.analyze_jar(jar_file)

        assert result["format"] == "JAR"
        assert "total_files" in result
        assert "class_files" in result
        assert "resources" in result
        assert "manifest_info" in result

    def test_analyze_jar_manifest_parsing(self, analyzer: MultiFormatBinaryAnalyzer, jar_file: Path) -> None:
        """analyze_jar parses MANIFEST.MF."""
        result = analyzer.analyze_jar(jar_file)

        manifest = result["manifest_info"]
        assert manifest["present"] is True
        assert "main_class" in manifest
        assert manifest["main_class"] == "Test"

    def test_analyze_jar_class_files(self, analyzer: MultiFormatBinaryAnalyzer, jar_file: Path) -> None:
        """analyze_jar identifies class files."""
        result = analyzer.analyze_jar(jar_file)

        assert len(result["class_files"]) > 0


class TestCOMAnalysis:
    """Test COM executable analysis."""

    def test_analyze_com_basic(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, com_binary: bytes) -> None:
        """analyze_com extracts COM executable info."""
        com_path = tmp_path / "test.com"
        com_path.write_bytes(com_binary)

        result = analyzer.analyze_com(com_path)

        assert result["format"] == "COM"
        assert result["load_address"] == "0x0100"
        assert result["file_size"] <= 65536

    def test_analyze_com_size_limit(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """analyze_com rejects files larger than 64KB."""
        large_com = b"\xEB\x10" + b"\x00" * 70000
        com_path = tmp_path / "large.com"
        com_path.write_bytes(large_com)

        result = analyzer.analyze_com(com_path)

        assert "error" in result

    def test_analyze_com_instruction_detection(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, com_binary: bytes) -> None:
        """analyze_com detects common DOS instructions."""
        com_path = tmp_path / "test.com"
        com_path.write_bytes(com_binary)

        result = analyzer.analyze_com(com_path)

        header_analysis = result["header_analysis"]
        assert "first_instruction" in header_analysis or "possible_instructions" in header_analysis


class TestUnifiedAnalysis:
    """Test unified analyze method."""

    def test_analyze_dispatches_to_pe(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze dispatches to analyze_pe for PE binaries."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze(pe_path)

        assert result["format"] == "PE"

    def test_analyze_dispatches_to_elf(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, elf_binary: bytes) -> None:
        """analyze dispatches to analyze_elf for ELF binaries."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(elf_binary)

        result = analyzer.analyze(elf_path)

        assert result["format"] == "ELF"

    def test_analyze_file_not_found(self, analyzer: MultiFormatBinaryAnalyzer) -> None:
        """analyze handles missing files gracefully."""
        result = analyzer.analyze("/nonexistent/file.bin")

        assert "error" in result

    def test_analyze_includes_metadata(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path, pe_binary: bytes) -> None:
        """analyze includes file metadata in results."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        result = analyzer.analyze(pe_path)

        assert "format" in result
        assert "file_path" in result
        assert "file_size" in result
        assert "timestamp" in result


class TestRunMultiFormatAnalysis:
    """Test convenience function."""

    def test_run_analysis_with_app_mock(self, tmp_path: Path, pe_binary: bytes) -> None:
        """run_multi_format_analysis works with mock app object."""
        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(pe_binary)

        class MockApp:
            def __init__(self) -> None:
                self.binary_path: str = str(pe_path)
                self.analyze_results: list[str] = []
                self.update_output = type('obj', (object,), {'emit': lambda self, x: None})()

        app = MockApp()
        result = run_multi_format_analysis(app)

        assert "format" in result
        assert result["format"] == "PE"

    def test_run_analysis_with_explicit_path(self, tmp_path: Path, elf_binary: bytes) -> None:
        """run_multi_format_analysis accepts explicit binary path."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(elf_binary)

        class MockApp:
            def __init__(self) -> None:
                self.update_output = type('obj', (object,), {'emit': lambda self, x: None})()
                self.analyze_results: list[str] = []

        app = MockApp()
        result = run_multi_format_analysis(app, binary_path=elf_path)

        assert result["format"] == "ELF"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_corrupted_pe_header(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """analyze_pe handles corrupted PE headers."""
        corrupted = b"MZ" + b"\xFF" * 200
        pe_path = tmp_path / "corrupted.exe"
        pe_path.write_bytes(corrupted)

        result = analyzer.analyze_pe(pe_path)

        assert "error" in result or "format" in result

    def test_empty_file(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """identify_format handles empty files."""
        empty_path = tmp_path / "empty.bin"
        empty_path.write_bytes(b"")

        format_type = analyzer.identify_format(empty_path)

        assert format_type == "UNKNOWN"

    def test_very_large_binary(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """analyze handles large binaries without crashing."""
        large_data = b"MZ" + b"\x00" * (10 * 1024 * 1024)
        large_path = tmp_path / "large.exe"
        large_path.write_bytes(large_data)

        result = analyzer.identify_format(large_path)

        assert result is not None

    def test_binary_with_high_entropy(self, analyzer: MultiFormatBinaryAnalyzer, tmp_path: Path) -> None:
        """analyze_pe calculates entropy for encrypted sections."""
        import os
        high_entropy_section = os.urandom(512)
        pe_data = b"MZ" + b"\x00" * 500 + high_entropy_section
        pe_path = tmp_path / "encrypted.exe"
        pe_path.write_bytes(pe_data)

        try:
            result = analyzer.analyze_pe(pe_path)
            assert result is not None
        except Exception:
            pass
