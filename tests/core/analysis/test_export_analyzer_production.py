"""Production-grade tests for PE Export Analyzer.

Tests validate real export table analysis on actual Windows DLLs and custom PE binaries.
All tests use REAL data - NO mocks, stubs, or simulations.

Tests cover:
- Export table parsing from real Windows DLLs (kernel32.dll, ntdll.dll, user32.dll)
- Export function enumeration and resolution
- Ordinal handling and name resolution
- Forwarded export detection
- License validation export detection
- Export name mangling/demangling
- Real address resolution
- Error handling for invalid export tables

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.export_analyzer import (
    ExportAnalyzer,
    ExportEntry,
    ForwardedExport,
    analyze_exports,
)


class TestExportAnalyzerInitialization:
    """Test ExportAnalyzer initialization and configuration."""

    def test_analyzer_initialization_with_real_dll(self) -> None:
        """ExportAnalyzer initializes correctly with real Windows DLL."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"

        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)

        assert analyzer.binary_path == kernel32_path
        assert analyzer.exports == []
        assert analyzer.export_directory is None
        assert analyzer.base_address == 0

    def test_analyzer_initialization_with_nonexistent_file(self) -> None:
        """ExportAnalyzer raises error for nonexistent files."""
        with pytest.raises(FileNotFoundError):
            ExportAnalyzer(r"C:\nonexistent\file.dll")


class TestRealWindowsDLLExportParsing:
    """Test export parsing on real Windows system DLLs."""

    @pytest.fixture
    def kernel32_path(self) -> str:
        """Path to kernel32.dll."""
        path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")
        return path

    @pytest.fixture
    def ntdll_path(self) -> str:
        """Path to ntdll.dll."""
        path: str = r"C:\Windows\System32\ntdll.dll"
        if not Path(path).exists():
            pytest.skip("ntdll.dll not found - Windows platform required")
        return path

    @pytest.fixture
    def user32_path(self) -> str:
        """Path to user32.dll."""
        path: str = r"C:\Windows\System32\user32.dll"
        if not Path(path).exists():
            pytest.skip("user32.dll not found - Windows platform required")
        return path

    def test_parse_kernel32_exports(self, kernel32_path: str) -> None:
        """Extracts and validates exports from real kernel32.dll."""
        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        assert len(analyzer.exports) > 1000
        assert analyzer.export_directory is not None

        export_names: list[str] = [exp.name for exp in analyzer.exports if exp.name]

        assert "CreateFileA" in export_names
        assert "CreateFileW" in export_names
        assert "ReadFile" in export_names
        assert "WriteFile" in export_names
        assert "VirtualAlloc" in export_names
        assert "LoadLibraryA" in export_names
        assert "GetProcAddress" in export_names

        for export in analyzer.exports[:100]:
            if export.name:
                if not export.is_forwarded:
                    assert export.address > 0
                assert export.ordinal > 0

    def test_parse_ntdll_exports(self, ntdll_path: str) -> None:
        """Extracts and validates exports from real ntdll.dll."""
        analyzer = ExportAnalyzer(ntdll_path)
        analyzer.analyze()

        assert len(analyzer.exports) > 1500

        export_names: list[str] = [exp.name for exp in analyzer.exports if exp.name]

        assert "NtCreateFile" in export_names
        assert "NtReadFile" in export_names
        assert "NtWriteFile" in export_names
        assert "RtlInitUnicodeString" in export_names
        assert "ZwQuerySystemInformation" in export_names

        common_prefixes: int = 0
        for export in analyzer.exports:
            if export.name:
                if not export.is_forwarded:
                    assert export.address > 0
                assert export.ordinal > 0
                if export.name.startswith(("Nt", "Rtl", "Zw", "Ldr", "Csr", "Tp")):
                    common_prefixes += 1

        assert common_prefixes > 1400

    def test_parse_user32_exports(self, user32_path: str) -> None:
        """Extracts and validates exports from real user32.dll."""
        analyzer = ExportAnalyzer(user32_path)
        analyzer.analyze()

        assert len(analyzer.exports) > 700

        export_names: list[str] = [exp.name for exp in analyzer.exports if exp.name]

        assert "MessageBoxA" in export_names
        assert "MessageBoxW" in export_names
        assert "CreateWindowExA" in export_names
        assert "CreateWindowExW" in export_names
        assert "ShowWindow" in export_names


class TestExportOrdinalHandling:
    """Test export ordinal resolution and handling."""

    def test_ordinal_to_function_resolution_kernel32(self) -> None:
        """Resolves export ordinals to function names in kernel32.dll."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        ordinal_map: dict[int, str] = {}
        for export in analyzer.exports:
            if export.name and export.ordinal:
                ordinal_map[export.ordinal] = export.name

        assert len(ordinal_map) > 1000

        export_by_ordinal: ExportEntry | None = analyzer.get_export_by_ordinal(1)
        assert export_by_ordinal is not None
        if not export_by_ordinal.is_forwarded:
            assert export_by_ordinal.address > 0

    def test_ordinal_only_exports_handling(self) -> None:
        """Handles exports that only have ordinals without names."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        ordinal_only_exports: list[ExportEntry] = [
            exp for exp in analyzer.exports if not exp.name and exp.ordinal
        ]

        if ordinal_only_exports:
            for export in ordinal_only_exports[:10]:
                assert export.ordinal > 0
                if not export.is_forwarded:
                    assert export.address > 0
                assert export.name is None or export.name == ""


class TestForwardedExportDetection:
    """Test detection and parsing of forwarded exports."""

    def test_detect_forwarded_exports_kernel32(self) -> None:
        """Detects forwarded exports in kernel32.dll (many forward to kernelbase.dll)."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        forwarded_exports: list[ExportEntry] = [
            exp for exp in analyzer.exports if exp.is_forwarded
        ]

        assert len(forwarded_exports) > 0

        for forwarded in forwarded_exports[:20]:
            assert forwarded.forward_name is not None
            assert "." in forwarded.forward_name
            assert forwarded.forward_dll is not None
            assert forwarded.forward_function is not None

    def test_parse_forwarded_export_format(self) -> None:
        """Parses forwarded export format correctly (DLL.Function)."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        forwarded_exports: list[ExportEntry] = [
            exp for exp in analyzer.exports if exp.is_forwarded
        ]

        if forwarded_exports:
            for forwarded in forwarded_exports[:10]:
                assert forwarded.forward_dll is not None
                assert forwarded.forward_function is not None

                parts: list[str] = forwarded.forward_name.split(".", 1)
                assert len(parts) == 2
                assert parts[0] == forwarded.forward_dll
                assert parts[1] == forwarded.forward_function


class TestExportAddressResolution:
    """Test export address calculation and RVA resolution."""

    def test_resolve_export_rva_to_virtual_address(self) -> None:
        """Resolves export RVA to virtual address using image base."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        assert analyzer.base_address > 0

        for export in analyzer.exports[:50]:
            if export.name and not export.is_forwarded:
                assert export.rva > 0
                assert export.address == analyzer.base_address + export.rva

    def test_export_addresses_within_image_bounds(self) -> None:
        """Export addresses fall within valid image memory bounds."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        image_size: int = analyzer.image_size

        for export in analyzer.exports:
            if not export.is_forwarded:
                assert export.rva < image_size
                assert export.rva > 0


class TestLicenseValidationExportDetection:
    """Test detection of license validation related exports."""

    @pytest.fixture
    def license_dll_binary(self, temp_workspace: Path) -> Path:
        """Create PE DLL with license validation exports."""
        dll_path: Path = temp_workspace / "license_check.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0x5F5E100C,
            0,
            0,
            224,
            0x2022,
        )

        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x10000000)
        optional_header[92:96] = struct.pack("<I", 0x1000)
        optional_header[96:100] = struct.pack("<I", 0x200)

        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".edata\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x400)
        section_header[20:24] = struct.pack("<I", 0x400)
        section_header[36:40] = struct.pack("<I", 0x40000040)

        export_names: list[bytes] = [
            b"ValidateLicense\x00",
            b"CheckActivation\x00",
            b"VerifySerial\x00",
            b"GetLicenseStatus\x00",
            b"RegisterProduct\x00",
            b"DeactivateLicense\x00",
        ]

        num_functions: int = len(export_names)
        export_dir_rva: int = 0x1000
        names_rva: int = export_dir_rva + 40
        ordinals_rva: int = names_rva + (num_functions * 4)
        functions_rva: int = ordinals_rva + (num_functions * 2)
        strings_rva: int = functions_rva + (num_functions * 4)

        export_directory: bytes = struct.pack(
            "<IIHHHIIIII",
            0,
            0,
            0,
            0,
            1,
            num_functions,
            num_functions,
            functions_rva,
            names_rva,
            ordinals_rva,
        )

        functions_table: bytes = b"".join(
            struct.pack("<I", 0x2000 + (i * 0x10)) for i in range(num_functions)
        )

        string_offset: int = 0
        name_offsets: list[int] = []
        name_strings: bytes = b""
        for name in export_names:
            name_offsets.append(strings_rva + string_offset)
            name_strings += name
            string_offset += len(name)

        names_table: bytes = b"".join(struct.pack("<I", offset) for offset in name_offsets)

        ordinals_table: bytes = b"".join(struct.pack("<H", i) for i in range(num_functions))

        export_section: bytes = (
            export_directory +
            names_table +
            ordinals_table +
            functions_table +
            name_strings +
            b"\x00" * (0x400 - len(export_directory + names_table + ordinals_table + functions_table + name_strings))
        )

        binary_data: bytes = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_header +
            b"\x00" * (0x400 - len(dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header)) +
            export_section
        )

        dll_path.write_bytes(binary_data)
        return dll_path

    def test_detect_license_validation_exports(self, license_dll_binary: Path) -> None:
        """Detects exports related to license validation."""
        analyzer = ExportAnalyzer(str(license_dll_binary))
        analyzer.analyze()

        license_exports: list[ExportEntry] = analyzer.get_license_related_exports()

        assert len(license_exports) >= 6

        license_names: list[str] = [exp.name for exp in license_exports]

        assert "ValidateLicense" in license_names
        assert "CheckActivation" in license_names
        assert "VerifySerial" in license_names
        assert "GetLicenseStatus" in license_names
        assert "RegisterProduct" in license_names
        assert "DeactivateLicense" in license_names

    def test_categorize_license_export_types(self, license_dll_binary: Path) -> None:
        """Categorizes license exports by validation type."""
        analyzer = ExportAnalyzer(str(license_dll_binary))
        analyzer.analyze()

        categories: dict[str, list[ExportEntry]] = analyzer.categorize_license_exports()

        assert "validation" in categories
        assert "activation" in categories
        assert "registration" in categories

        assert len(categories["validation"]) >= 2
        assert len(categories["activation"]) >= 1
        assert len(categories["registration"]) >= 1


class TestExportNameManglingDemangling:
    """Test C++ name mangling detection and demangling."""

    @pytest.fixture
    def cpp_dll_binary(self, temp_workspace: Path) -> Path:
        """Create PE DLL with C++ mangled export names."""
        dll_path: Path = temp_workspace / "cpp_exports.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0x5F5E100C,
            0,
            0,
            224,
            0x2022,
        )

        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x10000000)
        optional_header[92:96] = struct.pack("<I", 0x1000)
        optional_header[96:100] = struct.pack("<I", 0x200)

        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".edata\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x400)
        section_header[20:24] = struct.pack("<I", 0x400)
        section_header[36:40] = struct.pack("<I", 0x40000040)

        export_names: list[bytes] = [
            b"?ValidateLicense@@YAHH@Z\x00",
            b"?CheckActivation@@YA_NXZ\x00",
            b"??0LicenseManager@@QEAA@XZ\x00",
            b"??1LicenseManager@@QEAA@XZ\x00",
            b"?GetInstance@LicenseManager@@SAPEAV1@XZ\x00",
        ]

        num_functions: int = len(export_names)
        export_dir_rva: int = 0x1000
        names_rva: int = export_dir_rva + 40
        ordinals_rva: int = names_rva + (num_functions * 4)
        functions_rva: int = ordinals_rva + (num_functions * 2)
        strings_rva: int = functions_rva + (num_functions * 4)

        export_directory: bytes = struct.pack(
            "<IIHHHIIIII",
            0,
            0,
            0,
            0,
            1,
            num_functions,
            num_functions,
            functions_rva,
            names_rva,
            ordinals_rva,
        )

        functions_table: bytes = b"".join(
            struct.pack("<I", 0x2000 + (i * 0x10)) for i in range(num_functions)
        )

        string_offset: int = 0
        name_offsets: list[int] = []
        name_strings: bytes = b""
        for name in export_names:
            name_offsets.append(strings_rva + string_offset)
            name_strings += name
            string_offset += len(name)

        names_table: bytes = b"".join(struct.pack("<I", offset) for offset in name_offsets)

        ordinals_table: bytes = b"".join(struct.pack("<H", i) for i in range(num_functions))

        export_section: bytes = (
            export_directory +
            names_table +
            ordinals_table +
            functions_table +
            name_strings +
            b"\x00" * (0x400 - len(export_directory + names_table + ordinals_table + functions_table + name_strings))
        )

        binary_data: bytes = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_header +
            b"\x00" * (0x400 - len(dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header)) +
            export_section
        )

        dll_path.write_bytes(binary_data)
        return dll_path

    def test_detect_mangled_cpp_exports(self, cpp_dll_binary: Path) -> None:
        """Detects C++ mangled export names."""
        analyzer = ExportAnalyzer(str(cpp_dll_binary))
        analyzer.analyze()

        mangled_exports: list[ExportEntry] = [
            exp for exp in analyzer.exports if analyzer.is_mangled_name(exp.name)
        ]

        assert len(mangled_exports) == 5

        for export in mangled_exports:
            assert export.name.startswith("?")
            assert "@@" in export.name

    def test_demangle_cpp_export_names(self, cpp_dll_binary: Path) -> None:
        """Demangles C++ export names to readable format."""
        analyzer = ExportAnalyzer(str(cpp_dll_binary))
        analyzer.analyze()

        for export in analyzer.exports:
            if analyzer.is_mangled_name(export.name):
                demangled: str = analyzer.demangle_name(export.name)

                assert demangled != export.name
                assert not demangled.startswith("?")
                assert "@@" not in demangled


class TestExportTableErrorHandling:
    """Test error handling for invalid or corrupted export tables."""

    @pytest.fixture
    def corrupted_export_table_binary(self, temp_workspace: Path) -> Path:
        """Create PE with corrupted export table."""
        dll_path: Path = temp_workspace / "corrupted_exports.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0x5F5E100C,
            0,
            0,
            224,
            0x2022,
        )

        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x10000000)
        optional_header[92:96] = struct.pack("<I", 0xFFFFFFFF)
        optional_header[96:100] = struct.pack("<I", 0xFFFFFFFF)

        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".edata\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x400)
        section_header[20:24] = struct.pack("<I", 0x400)

        export_section: bytes = b"\xFF" * 0x400

        binary_data: bytes = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_header +
            b"\x00" * (0x400 - len(dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header)) +
            export_section
        )

        dll_path.write_bytes(binary_data)
        return dll_path

    def test_handle_corrupted_export_directory(self, corrupted_export_table_binary: Path) -> None:
        """Handles corrupted export directory gracefully."""
        analyzer = ExportAnalyzer(str(corrupted_export_table_binary))

        try:
            analyzer.analyze()
        except Exception as e:
            assert "export" in str(e).lower() or "corrupted" in str(e).lower()

    def test_handle_missing_export_table(self, temp_workspace: Path) -> None:
        """Handles PE with no export table."""
        dll_path: Path = temp_workspace / "no_exports.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0x5F5E100C,
            0,
            0,
            224,
            0x0122,
        )

        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)

        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x200)
        section_header[20:24] = struct.pack("<I", 0x400)

        binary_data: bytes = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_header +
            b"\x00" * 0x400
        )

        dll_path.write_bytes(binary_data)

        analyzer = ExportAnalyzer(str(dll_path))
        analyzer.analyze()

        assert len(analyzer.exports) == 0
        assert analyzer.export_directory is None

    def test_handle_invalid_export_rva(self, temp_workspace: Path) -> None:
        """Handles invalid export RVAs gracefully."""
        dll_path: Path = temp_workspace / "invalid_rva.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50

        pe_signature: bytes = b"PE\x00\x00"

        coff_header: bytes = struct.pack(
            "<HHIIIHH",
            0x014c,
            1,
            0x5F5E100C,
            0,
            0,
            224,
            0x2022,
        )

        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x10000000)
        optional_header[92:96] = struct.pack("<I", 0x1000)
        optional_header[96:100] = struct.pack("<I", 0x200)

        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".edata\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x400)
        section_header[20:24] = struct.pack("<I", 0x400)

        export_directory: bytes = struct.pack(
            "<IIHHHIIIII",
            0,
            0,
            0,
            0,
            1,
            2,
            2,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
        )

        export_section: bytes = export_directory + b"\x00" * (0x400 - len(export_directory))

        binary_data: bytes = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_header +
            b"\x00" * (0x400 - len(dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header)) +
            export_section
        )

        dll_path.write_bytes(binary_data)

        analyzer = ExportAnalyzer(str(dll_path))

        try:
            analyzer.analyze()
        except Exception as e:
            assert "rva" in str(e).lower() or "invalid" in str(e).lower() or "corrupted" in str(e).lower()


class TestAPIExportPatternAnalysis:
    """Test API export pattern analysis for security assessment."""

    def test_identify_cryptographic_api_exports(self) -> None:
        """Identifies cryptographic API exports in Windows DLLs."""
        advapi32_path: str = r"C:\Windows\System32\advapi32.dll"
        if not Path(advapi32_path).exists():
            pytest.skip("advapi32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(advapi32_path)
        analyzer.analyze()

        crypto_exports: list[ExportEntry] = analyzer.get_crypto_related_exports()

        assert len(crypto_exports) > 0

        crypto_names: list[str] = [exp.name for exp in crypto_exports]

        assert any("Crypt" in name for name in crypto_names)
        assert any("Hash" in name for name in crypto_names)

    def test_identify_registry_api_exports(self) -> None:
        """Identifies registry API exports in Windows DLLs."""
        advapi32_path: str = r"C:\Windows\System32\advapi32.dll"
        if not Path(advapi32_path).exists():
            pytest.skip("advapi32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(advapi32_path)
        analyzer.analyze()

        registry_exports: list[ExportEntry] = analyzer.get_registry_related_exports()

        assert len(registry_exports) > 0

        registry_names: list[str] = [exp.name for exp in registry_exports]

        assert any("Reg" in name for name in registry_names)

    def test_identify_network_api_exports(self) -> None:
        """Identifies network API exports in Windows DLLs."""
        ws2_32_path: str = r"C:\Windows\System32\ws2_32.dll"
        if not Path(ws2_32_path).exists():
            pytest.skip("ws2_32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(ws2_32_path)
        analyzer.analyze()

        network_exports: list[ExportEntry] = analyzer.get_network_related_exports()

        assert len(network_exports) > 0

        network_names: list[str] = [exp.name for exp in network_exports]

        assert "socket" in network_names or "WSASocket" in network_names
        assert "connect" in network_names or "WSAConnect" in network_names


class TestExportStatisticsGeneration:
    """Test export statistics and summary generation."""

    def test_generate_export_statistics_kernel32(self) -> None:
        """Generates comprehensive export statistics for kernel32.dll."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        stats: dict[str, Any] = analyzer.get_export_statistics()

        assert stats["total_exports"] > 1000
        assert stats["named_exports"] > 1000
        assert stats["forwarded_exports"] >= 0
        assert stats["ordinal_range"]["min"] > 0
        assert stats["ordinal_range"]["max"] > stats["ordinal_range"]["min"]

    def test_export_summary_includes_all_categories(self) -> None:
        """Export summary includes all relevant API categories."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        summary: dict[str, Any] = analyzer.get_export_summary()

        assert "total_exports" in summary
        assert "api_categories" in summary
        assert "file_operations" in summary["api_categories"]
        assert "memory_operations" in summary["api_categories"]
        assert "process_operations" in summary["api_categories"]


class TestExportSearchAndFiltering:
    """Test export search and filtering functionality."""

    def test_search_exports_by_name(self) -> None:
        """Searches exports by function name."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        file_exports: list[ExportEntry] = analyzer.search_exports("File")

        assert len(file_exports) > 10

        for export in file_exports:
            assert "File" in export.name or "file" in export.name.lower()

    def test_filter_exports_by_pattern(self) -> None:
        """Filters exports matching specific patterns."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = ExportAnalyzer(kernel32_path)
        analyzer.analyze()

        create_exports: list[ExportEntry] = analyzer.filter_exports_by_pattern(r"^Create")

        assert len(create_exports) > 10

        for export in create_exports:
            assert export.name.startswith("Create")


class TestFunctionalExportAnalysis:
    """Test functional export analysis for license cracking."""

    def test_analyze_license_check_export_usage(self, license_dll_binary: Path) -> None:
        """Analyzes how license check exports are used in binary."""
        analyzer = ExportAnalyzer(str(license_dll_binary))
        analyzer.analyze()

        license_exports: list[ExportEntry] = analyzer.get_license_related_exports()

        usage_analysis: dict[str, Any] = analyzer.analyze_export_usage(license_exports)

        assert "validation_functions" in usage_analysis
        assert "activation_functions" in usage_analysis
        assert len(usage_analysis["validation_functions"]) >= 2

    def test_identify_bypass_targets_from_exports(self, license_dll_binary: Path) -> None:
        """Identifies export functions that are potential bypass targets."""
        analyzer = ExportAnalyzer(str(license_dll_binary))
        analyzer.analyze()

        bypass_targets: list[ExportEntry] = analyzer.identify_bypass_targets()

        assert len(bypass_targets) > 0

        target_names: list[str] = [exp.name for exp in bypass_targets]

        assert any(
            name in target_names
            for name in ["ValidateLicense", "CheckActivation", "VerifySerial"]
        )


class TestExportComparison:
    """Test export comparison between different binaries."""

    def test_compare_exports_between_versions(self, temp_workspace: Path) -> None:
        """Compares exports between different versions of same DLL."""
        v1_path: Path = temp_workspace / "license_v1.dll"
        v2_path: Path = temp_workspace / "license_v2.dll"

        dos_header: bytearray = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

        dos_stub: bytes = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + b"\x00" * 50
        pe_signature: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x014c, 1, 0x5F5E100C, 0, 0, 224, 0x2022)
        optional_header: bytearray = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x10000000)
        optional_header[92:96] = struct.pack("<I", 0x1000)
        optional_header[96:100] = struct.pack("<I", 0x200)
        section_header: bytearray = bytearray(40)
        section_header[0:8] = b".edata\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x400)
        section_header[20:24] = struct.pack("<I", 0x400)

        v1_exports: list[bytes] = [b"ValidateLicense\x00", b"CheckActivation\x00", b"VerifySerial\x00"]
        v2_exports: list[bytes] = [b"ValidateLicense\x00", b"CheckActivation\x00", b"VerifySerial\x00", b"GetLicenseInfo\x00"]

        for version_path, export_names in [(v1_path, v1_exports), (v2_path, v2_exports)]:
            num_functions: int = len(export_names)
            export_dir_rva: int = 0x1000
            names_rva: int = export_dir_rva + 40
            ordinals_rva: int = names_rva + (num_functions * 4)
            functions_rva: int = ordinals_rva + (num_functions * 2)
            strings_rva: int = functions_rva + (num_functions * 4)

            export_directory: bytes = struct.pack("<IIHHHIIIII", 0, 0, 0, 0, 1, num_functions, num_functions, functions_rva, names_rva, ordinals_rva)
            functions_table: bytes = b"".join(struct.pack("<I", 0x2000 + (i * 0x10)) for i in range(num_functions))

            string_offset: int = 0
            name_offsets: list[int] = []
            name_strings: bytes = b""
            for name in export_names:
                name_offsets.append(strings_rva + string_offset)
                name_strings += name
                string_offset += len(name)

            names_table: bytes = b"".join(struct.pack("<I", offset) for offset in name_offsets)
            ordinals_table: bytes = b"".join(struct.pack("<H", i) for i in range(num_functions))

            export_section: bytes = (
                export_directory + names_table + ordinals_table + functions_table + name_strings +
                b"\x00" * (0x400 - len(export_directory + names_table + ordinals_table + functions_table + name_strings))
            )

            binary_data: bytes = (
                dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header +
                b"\x00" * (0x400 - len(dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header)) +
                export_section
            )

            version_path.write_bytes(binary_data)

        analyzer_v1 = ExportAnalyzer(str(v1_path))
        analyzer_v1.analyze()

        analyzer_v2 = ExportAnalyzer(str(v2_path))
        analyzer_v2.analyze()

        comparison: dict[str, Any] = ExportAnalyzer.compare_exports(analyzer_v1, analyzer_v2)

        assert "added_exports" in comparison
        assert "removed_exports" in comparison
        assert "common_exports" in comparison

        assert len(comparison["added_exports"]) == 1
        assert comparison["added_exports"][0].name == "GetLicenseInfo"
        assert len(comparison["removed_exports"]) == 0
        assert len(comparison["common_exports"]) == 3


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Create temporary workspace for test files."""
    workspace: Path = tmp_path / "export_analyzer_tests"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def test_convenience_function_analyze_exports() -> None:
    """Convenience function analyzes exports from binary path."""
    kernel32_path: str = r"C:\Windows\System32\kernel32.dll"
    if not Path(kernel32_path).exists():
        pytest.skip("kernel32.dll not found - Windows platform required")

    result: dict[str, Any] = analyze_exports(kernel32_path)

    assert "exports" in result
    assert "statistics" in result
    assert "summary" in result
    assert len(result["exports"]) > 1000
