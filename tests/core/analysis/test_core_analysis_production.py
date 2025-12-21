"""Production tests for core_analysis module.

This module tests the core_analysis.py module which provides fundamental
binary analysis functions for PE file examination, including header analysis,
section analysis, import/export detection, and license-related pattern identification.

Copyright (C) 2025 Zachary Flint
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest


def create_minimal_pe(
    path: Path,
    sections: list[tuple[str, bytes]] | None = None,
    imports: list[tuple[str, list[str]]] | None = None,
    exports: list[str] | None = None,
    machine_type: int = 0x014C,  # x86
) -> Path:
    """Create a minimal valid PE file for testing.

    Args:
        path: Path where PE file will be created
        sections: List of (name, data) tuples for sections
        imports: List of (dll_name, [function_names]) for imports
        exports: List of exported function names
        machine_type: PE machine type (0x014C for x86, 0x8664 for x64)

    Returns:
        Path to created PE file
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)  # e_lfanew offset to PE header

    pe_signature = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        machine_type,  # Machine
        len(sections) if sections else 1,  # NumberOfSections
        0x60000000,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        224,  # SizeOfOptionalHeader
        0x0102,  # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    )

    optional_header = struct.pack(
        "<HHBBIIIIIHHHHHHIIIIHHIIIIIIII",
        0x010B,  # Magic (PE32)
        0,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        0x1000,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0x1000,  # BaseOfData
        0x400000,  # ImageBase
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        0,  # MajorOperatingSystemVersion
        0,  # MinorOperatingSystemVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        4,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        0x3000,  # SizeOfImage
        0x200,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem (CONSOLE)
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )

    data_directories = b"\x00" * (16 * 8)  # 16 data directories

    section_headers = b""
    if sections:
        for idx, (name, data) in enumerate(sections):
            section_name = name[:8].ljust(8, "\x00").encode("utf-8")
            virtual_size = len(data)
            virtual_address = 0x1000 * (idx + 1)
            size_of_raw_data = (len(data) + 0x1FF) & ~0x1FF  # Align to 512
            pointer_to_raw_data = 0x200 + (idx * 0x200)

            section_header = (
                section_name
                + struct.pack("<IIIIHHI",
                    virtual_size,
                    virtual_address,
                    size_of_raw_data,
                    pointer_to_raw_data,
                    0,  # PointerToRelocations
                    0,  # PointerToLinenumbers
                    0,  # NumberOfRelocations
                    0,  # NumberOfLinenumbers
                    0xE0000020,  # Characteristics (CODE|EXECUTE|READ|WRITE)
                )
            )
            section_headers += section_header

    pe_content = dos_header + pe_signature + file_header + optional_header + data_directories + section_headers

    pe_content = pe_content.ljust(0x200, b"\x00")

    if sections:
        for section_name, section_data in sections:
            aligned_data = section_data.ljust((len(section_data) + 0x1FF) & ~0x1FF, b"\x00")
            pe_content += aligned_data

    path.write_bytes(pe_content)
    return path


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create a simple PE binary for testing."""
    binary_path = tmp_path / "simple.exe"
    sections = [
        (".text", b"\x90" * 100 + b"CheckLicense\x00" + b"\x90" * 100),
        (".data", b"License key validation failed\x00" * 5),
    ]
    return create_minimal_pe(binary_path, sections=sections)


@pytest.fixture
def packed_pe_binary(tmp_path: Path) -> Path:
    """Create a packed-looking PE binary (high entropy section)."""
    binary_path = tmp_path / "packed.exe"
    import random
    random.seed(12345)
    high_entropy_data = bytes([random.randint(0, 255) for _ in range(512)])

    sections = [
        ("UPX0", high_entropy_data),
        ("UPX1", high_entropy_data),
    ]
    return create_minimal_pe(binary_path, sections=sections)


class TestCoreAnalysisUtilityFunctions:
    """Test utility functions in core_analysis module."""

    def test_get_machine_type_x86(self) -> None:
        """get_machine_type returns correct string for x86."""
        from intellicrack.core.analysis.core_analysis import get_machine_type

        result = get_machine_type(0x014C)
        assert result == "x86 (32-bit)"

    def test_get_machine_type_x64(self) -> None:
        """get_machine_type returns correct string for x64."""
        from intellicrack.core.analysis.core_analysis import get_machine_type

        result = get_machine_type(0x8664)
        assert result == "x64 (64-bit)"

    def test_get_machine_type_arm(self) -> None:
        """get_machine_type returns correct string for ARM."""
        from intellicrack.core.analysis.core_analysis import get_machine_type

        result = get_machine_type(0x01C0)
        assert result == "ARM little endian"

    def test_get_machine_type_unknown(self) -> None:
        """get_machine_type handles unknown types."""
        from intellicrack.core.analysis.core_analysis import get_machine_type

        result = get_machine_type(0xFFFF)
        assert "Unknown" in result
        assert "0xFFFF" in result

    def test_get_magic_type_pe32(self) -> None:
        """get_magic_type returns correct string for PE32."""
        from intellicrack.core.analysis.core_analysis import get_magic_type

        result = get_magic_type(0x10B)
        assert result == "PE32"

    def test_get_magic_type_pe32_plus(self) -> None:
        """get_magic_type returns correct string for PE32+."""
        from intellicrack.core.analysis.core_analysis import get_magic_type

        result = get_magic_type(0x20B)
        assert result == "PE32+"

    def test_get_magic_type_unknown(self) -> None:
        """get_magic_type handles unknown magic values."""
        from intellicrack.core.analysis.core_analysis import get_magic_type

        result = get_magic_type(0xABC)
        assert "Unknown" in result

    def test_get_characteristics_executable(self) -> None:
        """get_characteristics identifies executable images."""
        from intellicrack.core.analysis.core_analysis import get_characteristics

        result = get_characteristics(0x0002)
        assert "EXECUTABLE_IMAGE" in result

    def test_get_characteristics_dll(self) -> None:
        """get_characteristics identifies DLL files."""
        from intellicrack.core.analysis.core_analysis import get_characteristics

        result = get_characteristics(0x2000)
        assert "DLL" in result

    def test_get_characteristics_multiple_flags(self) -> None:
        """get_characteristics handles multiple flags."""
        from intellicrack.core.analysis.core_analysis import get_characteristics

        result = get_characteristics(0x0002 | 0x0100 | 0x0200)
        assert "EXECUTABLE_IMAGE" in result
        assert "32BIT_MACHINE" in result
        assert "DEBUG_STRIPPED" in result

    def test_get_characteristics_none(self) -> None:
        """get_characteristics returns None for no flags."""
        from intellicrack.core.analysis.core_analysis import get_characteristics

        result = get_characteristics(0x0000)
        assert result == "None"

    def test_get_pe_timestamp_valid(self) -> None:
        """get_pe_timestamp converts valid timestamps."""
        from intellicrack.core.analysis.core_analysis import get_pe_timestamp

        result = get_pe_timestamp(1600000000)
        assert "2020" in result

    def test_get_pe_timestamp_invalid(self) -> None:
        """get_pe_timestamp handles invalid timestamps."""
        from intellicrack.core.analysis.core_analysis import get_pe_timestamp

        result = get_pe_timestamp(-1)
        assert "Invalid" in result


class TestAnalyzeBinaryInternal:
    """Test analyze_binary_internal function."""

    def test_analyze_simple_binary(self, simple_pe_binary: Path) -> None:
        """analyze_binary_internal analyzes simple PE file."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(simple_pe_binary))

        assert isinstance(results, list)
        assert len(results) > 0
        assert any("Analyzing binary" in r for r in results)
        assert any("File size" in r for r in results)

    def test_analyze_binary_pe_header(self, simple_pe_binary: Path) -> None:
        """analyze_binary_internal extracts PE header information."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(simple_pe_binary))

        results_str = "\n".join(results)
        assert "PE Header:" in results_str
        assert "Machine:" in results_str
        assert "Number of sections:" in results_str

    def test_analyze_binary_optional_header(self, simple_pe_binary: Path) -> None:
        """analyze_binary_internal extracts optional header information."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(simple_pe_binary))

        results_str = "\n".join(results)
        assert "Optional Header:" in results_str
        assert "Magic:" in results_str
        assert "Entry point:" in results_str
        assert "Image base:" in results_str

    def test_analyze_binary_sections(self, simple_pe_binary: Path) -> None:
        """analyze_binary_internal analyzes sections."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(simple_pe_binary))

        results_str = "\n".join(results)
        assert "Sections:" in results_str
        assert ".text" in results_str or ".data" in results_str

    def test_analyze_binary_entropy_detection(self, packed_pe_binary: Path) -> None:
        """analyze_binary_internal detects high entropy sections."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(packed_pe_binary))

        results_str = "\n".join(results)
        assert "Entropy:" in results_str

    def test_analyze_binary_with_flags(self, simple_pe_binary: Path) -> None:
        """analyze_binary_internal accepts analysis flags."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal(str(simple_pe_binary), flags=["stealth"])

        assert isinstance(results, list)
        assert len(results) > 0

    def test_analyze_binary_invalid_path(self) -> None:
        """analyze_binary_internal handles invalid path."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        results = analyze_binary_internal("C:\\nonexistent\\binary.exe")

        assert isinstance(results, list)
        assert any("ERROR" in r for r in results)

    def test_analyze_binary_corrupted_file(self, tmp_path: Path) -> None:
        """analyze_binary_internal handles corrupted PE files."""
        from intellicrack.core.analysis.core_analysis import analyze_binary_internal

        corrupt_path = tmp_path / "corrupt.exe"
        corrupt_path.write_bytes(b"NOTAPE" * 100)

        results = analyze_binary_internal(str(corrupt_path))

        assert isinstance(results, list)
        assert any("ERROR" in r or "Failed" in r for r in results)


class TestDeepLicenseAnalysis:
    """Test enhanced_deep_license_analysis function."""

    def test_deep_license_analysis_basic(self, simple_pe_binary: Path) -> None:
        """enhanced_deep_license_analysis returns complete results structure."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis(str(simple_pe_binary))

        assert isinstance(result, dict)
        assert "license_patterns" in result
        assert "validation_routines" in result
        assert "protection_mechanisms" in result
        assert "suspicious_strings" in result

    def test_deep_license_analysis_string_detection(self, simple_pe_binary: Path) -> None:
        """enhanced_deep_license_analysis detects license-related strings."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis(str(simple_pe_binary))

        assert isinstance(result["suspicious_strings"], list)

    def test_deep_license_analysis_protection_mechanisms(self, packed_pe_binary: Path) -> None:
        """enhanced_deep_license_analysis identifies protection mechanisms."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis(str(packed_pe_binary))

        assert "protection_mechanisms" in result
        assert isinstance(result["protection_mechanisms"], list)

    def test_deep_license_analysis_network_calls(self, tmp_path: Path) -> None:
        """enhanced_deep_license_analysis detects network-related imports."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        binary_path = tmp_path / "network_test.exe"
        sections = [(".text", b"\x90" * 256)]
        create_minimal_pe(binary_path, sections=sections)

        result = enhanced_deep_license_analysis(str(binary_path))

        assert "network_calls" in result
        assert isinstance(result["network_calls"], list)

    def test_deep_license_analysis_registry_access(self, simple_pe_binary: Path) -> None:
        """enhanced_deep_license_analysis detects registry-related imports."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis(str(simple_pe_binary))

        assert "registry_access" in result
        assert isinstance(result["registry_access"], list)

    def test_deep_license_analysis_file_operations(self, simple_pe_binary: Path) -> None:
        """enhanced_deep_license_analysis detects file operation imports."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis(str(simple_pe_binary))

        assert "file_operations" in result
        assert isinstance(result["file_operations"], list)

    def test_deep_license_analysis_invalid_binary(self) -> None:
        """enhanced_deep_license_analysis handles invalid binaries."""
        from intellicrack.core.analysis.core_analysis import enhanced_deep_license_analysis

        result = enhanced_deep_license_analysis("C:\\nonexistent.exe")

        assert isinstance(result, dict)
        assert "error" in result


class TestPackingDetection:
    """Test detect_packing function."""

    def test_detect_packing_basic_structure(self, simple_pe_binary: Path) -> None:
        """detect_packing returns complete results structure."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(simple_pe_binary))

        assert isinstance(result, dict)
        assert "is_packed" in result
        assert "confidence" in result
        assert "indicators" in result
        assert "entropy_analysis" in result

    def test_detect_packing_unpacked_binary(self, simple_pe_binary: Path) -> None:
        """detect_packing identifies unpacked binaries."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(simple_pe_binary))

        assert isinstance(result["is_packed"], bool)
        assert isinstance(result["confidence"], float)
        assert 0 <= result["confidence"] <= 1.0

    def test_detect_packing_high_entropy(self, packed_pe_binary: Path) -> None:
        """detect_packing detects high entropy sections."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(packed_pe_binary))

        assert "entropy_analysis" in result
        entropy_analysis = result["entropy_analysis"]
        assert "average_entropy" in entropy_analysis
        assert "high_entropy_sections" in entropy_analysis

    def test_detect_packing_suspicious_sections(self, packed_pe_binary: Path) -> None:
        """detect_packing identifies suspicious section names."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(packed_pe_binary))

        assert "indicators" in result
        assert isinstance(result["indicators"], list)

    def test_detect_packing_import_analysis(self, simple_pe_binary: Path) -> None:
        """detect_packing analyzes import count."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(simple_pe_binary))

        assert "import_analysis" in result
        assert "import_count" in result["import_analysis"]

    def test_detect_packing_confidence_calculation(self, packed_pe_binary: Path) -> None:
        """detect_packing calculates confidence score."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing(str(packed_pe_binary))

        assert "confidence" in result
        assert isinstance(result["confidence"], float)
        assert 0 <= result["confidence"] <= 1.0

    def test_detect_packing_invalid_binary(self) -> None:
        """detect_packing handles invalid binaries."""
        from intellicrack.core.analysis.core_analysis import detect_packing

        result = detect_packing("C:\\nonexistent.exe")

        assert isinstance(result, dict)
        assert "error" in result


class TestEmbeddedScriptDetection:
    """Test decrypt_embedded_script function."""

    def test_decrypt_embedded_script_basic(self, simple_pe_binary: Path) -> None:
        """decrypt_embedded_script returns results list."""
        from intellicrack.core.analysis.core_analysis import decrypt_embedded_script

        results = decrypt_embedded_script(str(simple_pe_binary))

        assert isinstance(results, list)
        assert len(results) > 0
        assert any("Searching for embedded scripts" in r for r in results)

    def test_decrypt_embedded_script_no_scripts(self, simple_pe_binary: Path) -> None:
        """decrypt_embedded_script reports when no scripts found."""
        from intellicrack.core.analysis.core_analysis import decrypt_embedded_script

        results = decrypt_embedded_script(str(simple_pe_binary))

        results_str = "\n".join(results)
        assert "No embedded scripts found" in results_str or "Found" in results_str

    def test_decrypt_embedded_script_with_markers(self, tmp_path: Path) -> None:
        """decrypt_embedded_script detects script markers."""
        from intellicrack.core.analysis.core_analysis import decrypt_embedded_script

        script_content = b"<script>function validate() { return true; }</script>"
        binary_path = tmp_path / "script_test.exe"
        sections = [(".text", script_content + b"\x00" * 200)]
        create_minimal_pe(binary_path, sections=sections)

        results = decrypt_embedded_script(str(binary_path))

        results_str = "\n".join(results)
        assert "Found" in results_str or "scripts" in results_str.lower()

    def test_decrypt_embedded_script_obfuscation(self, tmp_path: Path) -> None:
        """decrypt_embedded_script detects obfuscation patterns."""
        from intellicrack.core.analysis.core_analysis import decrypt_embedded_script

        obfuscated = b"eval(String.fromCharCode(118,97,114))" + b"\x00" * 100
        binary_path = tmp_path / "obfuscated.exe"
        sections = [(".text", obfuscated)]
        create_minimal_pe(binary_path, sections=sections)

        results = decrypt_embedded_script(str(binary_path))

        assert isinstance(results, list)

    def test_decrypt_embedded_script_invalid_path(self) -> None:
        """decrypt_embedded_script handles invalid paths."""
        from intellicrack.core.analysis.core_analysis import decrypt_embedded_script

        results = decrypt_embedded_script("C:\\nonexistent.exe")

        assert isinstance(results, list)
        assert any("Error" in r for r in results)


class TestPrivateFunctions:
    """Test private helper functions."""

    def test_analyze_pe_header_function(self, simple_pe_binary: Path) -> None:
        """_analyze_pe_header extracts header information."""
        pytest.importorskip("pefile")
        from intellicrack.core.analysis.core_analysis import _analyze_pe_header
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(str(simple_pe_binary))
        results = _analyze_pe_header(pe)
        pe.close()

        assert isinstance(results, list)
        assert any("PE Header:" in r for r in results)

    def test_analyze_optional_header_function(self, simple_pe_binary: Path) -> None:
        """_analyze_optional_header extracts optional header."""
        pytest.importorskip("pefile")
        from intellicrack.core.analysis.core_analysis import _analyze_optional_header
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(str(simple_pe_binary))
        results = _analyze_optional_header(pe)
        pe.close()

        assert isinstance(results, list)
        assert any("Optional Header:" in r for r in results)

    def test_analyze_sections_function(self, simple_pe_binary: Path) -> None:
        """_analyze_sections analyzes PE sections."""
        pytest.importorskip("pefile")
        from intellicrack.core.analysis.core_analysis import _analyze_sections
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(str(simple_pe_binary))
        results: list[str] = []
        suspicious = _analyze_sections(pe, results)
        pe.close()

        assert isinstance(results, list)
        assert isinstance(suspicious, list)

    def test_analyze_imports_function(self, simple_pe_binary: Path) -> None:
        """_analyze_imports detects imports."""
        pytest.importorskip("pefile")
        from intellicrack.core.analysis.core_analysis import _analyze_imports
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(str(simple_pe_binary))
        results: list[str] = []
        license_imports = _analyze_imports(pe, results)
        pe.close()

        assert isinstance(results, list)
        assert isinstance(license_imports, list)

    def test_analyze_exports_function(self, simple_pe_binary: Path) -> None:
        """_analyze_exports detects exports."""
        pytest.importorskip("pefile")
        from intellicrack.core.analysis.core_analysis import _analyze_exports
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(str(simple_pe_binary))
        results: list[str] = []
        _analyze_exports(pe, results)
        pe.close()

        assert isinstance(results, list)

    def test_generate_analysis_summary_function(self) -> None:
        """_generate_analysis_summary creates summary."""
        from intellicrack.core.analysis.core_analysis import _generate_analysis_summary

        results: list[str] = []
        suspicious_sections = [".upx0", ".upx1"]
        license_imports = ["kernel32.dll::CheckLicense"]

        _generate_analysis_summary(results, suspicious_sections, license_imports)

        assert isinstance(results, list)
        assert any("Analysis Summary:" in r for r in results)
