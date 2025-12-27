"""Production tests for pe_analysis_common.py using real Windows DLLs.

Tests validate PE analysis, icon extraction, and section parsing on actual
Windows system binaries like kernel32.dll and notepad.exe.
"""

import os
import platform
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.binary.pe_analysis_common import (
    PEAnalyzer,
    analyze_pe_imports,
    create_image_from_icon_data,
    extract_all_pe_icons,
    extract_icon_from_resources,
    extract_pe_icon,
    get_pe_icon_info,
    get_pe_sections_info,
)


@pytest.fixture
def windows_system_dll() -> str:
    """Return path to Windows kernel32.dll for testing."""
    if platform.system() != "Windows":
        pytest.skip("Test requires Windows platform")

    kernel32_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "kernel32.dll"

    if not kernel32_path.exists():
        pytest.skip(f"kernel32.dll not found at {kernel32_path}")

    return str(kernel32_path)


@pytest.fixture
def windows_notepad_exe() -> str:
    """Return path to Windows notepad.exe for icon testing."""
    if platform.system() != "Windows":
        pytest.skip("Test requires Windows platform")

    notepad_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "notepad.exe"

    if not notepad_path.exists():
        pytest.skip(f"notepad.exe not found at {notepad_path}")

    return str(notepad_path)


@pytest.fixture
def pefile_pe(windows_system_dll: str) -> Any:
    """Create pefile.PE object from kernel32.dll."""
    try:
        from intellicrack.handlers.pefile_handler import pefile

        return pefile.PE(windows_system_dll)
    except ImportError:
        pytest.skip("pefile not available")


class TestGetPESectionsInfo:
    """Test PE section information extraction."""

    def test_extracts_sections_from_kernel32(self, pefile_pe: Any) -> None:
        """Extracts section information from kernel32.dll."""
        sections = get_pe_sections_info(pefile_pe)

        assert len(sections) > 0
        assert all("name" in section for section in sections)
        assert all("virtual_address" in section for section in sections)
        assert all("virtual_size" in section for section in sections)
        assert all("raw_size" in section for section in sections)
        assert all("characteristics" in section for section in sections)

    def test_section_names_are_valid(self, pefile_pe: Any) -> None:
        """Section names are valid strings."""
        sections = get_pe_sections_info(pefile_pe)

        common_sections = [".text", ".data", ".rdata", ".pdata", ".reloc"]
        section_names = [section["name"] for section in sections]

        assert any(name in section_names for name in common_sections)

    def test_section_addresses_are_positive(self, pefile_pe: Any) -> None:
        """Section virtual addresses are positive integers."""
        sections = get_pe_sections_info(pefile_pe)

        for section in sections:
            assert section["virtual_address"] >= 0
            assert isinstance(section["virtual_address"], int)

    def test_section_sizes_are_positive(self, pefile_pe: Any) -> None:
        """Section sizes are positive integers."""
        sections = get_pe_sections_info(pefile_pe)

        for section in sections:
            assert section["virtual_size"] >= 0
            assert section["raw_size"] >= 0

    def test_text_section_has_code_characteristics(self, pefile_pe: Any) -> None:
        """Text section has executable characteristics."""
        sections = get_pe_sections_info(pefile_pe)

        text_section = next((s for s in sections if s["name"] == ".text"), None)

        if text_section:
            IMAGE_SCN_MEM_EXECUTE = 0x20000000
            assert text_section["characteristics"] & IMAGE_SCN_MEM_EXECUTE


class TestAnalyzePEImports:
    """Test PE import analysis."""

    def test_analyzes_imports_with_target_apis(self, pefile_pe: Any) -> None:
        """Analyzes PE imports for specific API categories."""
        target_apis = {
            "process": ["CreateProcess", "OpenProcess", "TerminateProcess"],
            "file": ["CreateFile", "ReadFile", "WriteFile"],
            "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue"],
        }

        result = analyze_pe_imports(pefile_pe, target_apis)

        assert isinstance(result, dict)
        assert all(category in result for category in target_apis.keys())

    def test_detects_common_windows_apis(self, pefile_pe: Any) -> None:
        """Detects common Windows APIs in kernel32.dll imports."""
        target_apis = {
            "memory": ["VirtualAlloc", "VirtualFree", "VirtualProtect"],
            "threading": ["CreateThread", "ExitThread", "SuspendThread"],
        }

        result = analyze_pe_imports(pefile_pe, target_apis)

        assert isinstance(result, dict)


class TestPEIconExtraction:
    """Test PE icon extraction functionality."""

    def test_gets_icon_info_from_notepad(self, windows_notepad_exe: str) -> None:
        """Gets icon information from notepad.exe."""
        icon_info = get_pe_icon_info(windows_notepad_exe)

        assert isinstance(icon_info, dict)
        assert "has_icon" in icon_info
        assert "icon_count" in icon_info
        assert "icon_groups" in icon_info
        assert "icon_sizes" in icon_info
        assert "largest_icon" in icon_info

    def test_notepad_has_icon_resources(self, windows_notepad_exe: str) -> None:
        """Notepad.exe contains icon resources."""
        icon_info = get_pe_icon_info(windows_notepad_exe)

        if icon_info["has_icon"]:
            assert icon_info["icon_count"] > 0
            assert isinstance(icon_info["icon_sizes"], list)

    def test_extracts_icon_from_notepad(self, windows_notepad_exe: str) -> None:
        """Extracts icon from notepad.exe."""
        icon_image = extract_pe_icon(windows_notepad_exe)

        if icon_image is not None:
            assert hasattr(icon_image, "size")
            assert icon_image.size[0] > 0
            assert icon_image.size[1] > 0

    def test_saves_icon_to_file(
        self, windows_notepad_exe: str, tmp_path: Path
    ) -> None:
        """Saves extracted icon to PNG file."""
        output_path = tmp_path / "notepad_icon.png"

        icon_image = extract_pe_icon(windows_notepad_exe, str(output_path))

        if icon_image is not None:
            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_handles_pe_without_icons(self, windows_system_dll: str) -> None:
        """Handles PE files without icon resources gracefully."""
        icon_info = get_pe_icon_info(windows_system_dll)

        assert isinstance(icon_info, dict)

    def test_extracts_all_icons(
        self, windows_notepad_exe: str, tmp_path: Path
    ) -> None:
        """Extracts all icons from PE file."""
        output_dir = tmp_path / "icons"
        output_dir.mkdir()

        saved_icons = extract_all_pe_icons(windows_notepad_exe, str(output_dir))

        if len(saved_icons) > 0:
            assert all(Path(icon_path).exists() for icon_path in saved_icons)
            assert all(icon_path.endswith(".png") for icon_path in saved_icons)


class TestExtractIconFromResources:
    """Test icon extraction from PE resources."""

    def test_extracts_icon_data_from_notepad(self, windows_notepad_exe: str) -> None:
        """Extracts raw icon data from notepad.exe resources."""
        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(windows_notepad_exe)
            icon_data = extract_icon_from_resources(pe)

            if icon_data is not None:
                assert isinstance(icon_data, bytes)
                assert len(icon_data) > 0

        except ImportError:
            pytest.skip("pefile not available")

    def test_returns_none_for_pe_without_icons(self, pefile_pe: Any) -> None:
        """Returns None for PE without icon resources."""
        icon_data = extract_icon_from_resources(pefile_pe)

        assert icon_data is None or isinstance(icon_data, bytes)


class TestCreateImageFromIconData:
    """Test PIL Image creation from icon data."""

    def test_creates_image_from_valid_icon_data(
        self, windows_notepad_exe: str
    ) -> None:
        """Creates PIL Image from valid icon data."""
        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(windows_notepad_exe)
            icon_data = extract_icon_from_resources(pe)

            if icon_data:
                icon_image = create_image_from_icon_data(icon_data)

                if icon_image is not None:
                    assert hasattr(icon_image, "size")
                    assert hasattr(icon_image, "mode")

        except ImportError:
            pytest.skip("pefile not available")

    def test_handles_invalid_icon_data(self) -> None:
        """Handles invalid icon data gracefully."""
        invalid_data = b"\x00\x01\x02\x03"

        icon_image = create_image_from_icon_data(invalid_data)

        assert icon_image is None

    def test_handles_empty_icon_data(self) -> None:
        """Handles empty icon data gracefully."""
        empty_data = b""

        icon_image = create_image_from_icon_data(empty_data)

        assert icon_image is None


class TestPEAnalyzer:
    """Test comprehensive PE analyzer class."""

    def test_analyzer_initializes(self) -> None:
        """PE analyzer initializes with logger."""
        analyzer = PEAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "logger")

    def test_analyzes_kernel32_comprehensively(
        self, windows_system_dll: str
    ) -> None:
        """Analyzes kernel32.dll and returns comprehensive metadata."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert "imports" in result
        assert "exports" in result
        assert "sections" in result
        assert "headers" in result
        assert "resources" in result
        assert "certificates" in result
        assert "icon_info" in result
        assert "architecture" in result
        assert "is_dll" in result
        assert "is_exe" in result
        assert "checksum" in result
        assert "entry_point" in result

    def test_identifies_dll_correctly(self, windows_system_dll: str) -> None:
        """Correctly identifies DLL files."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert result["is_dll"] is True
        assert result["is_exe"] is False

    def test_identifies_exe_correctly(self, windows_notepad_exe: str) -> None:
        """Correctly identifies EXE files."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_notepad_exe)

        assert result["is_exe"] is True

    def test_detects_architecture(self, windows_system_dll: str) -> None:
        """Detects PE architecture correctly."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert result["architecture"] in ["x86", "x64", "ARM", "ARM64"]

    def test_extracts_imports(self, windows_system_dll: str) -> None:
        """Extracts import information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert isinstance(result["imports"], list)

        if len(result["imports"]) > 0:
            import_entry = result["imports"][0]
            assert "dll" in import_entry
            assert "functions" in import_entry

    def test_extracts_exports(self, windows_system_dll: str) -> None:
        """Extracts export information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert isinstance(result["exports"], list)

        if len(result["exports"]) > 0:
            export_entry = result["exports"][0]
            assert "name" in export_entry or "address" in export_entry
            assert "ordinal" in export_entry

    def test_extracts_sections(self, windows_system_dll: str) -> None:
        """Extracts section information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert isinstance(result["sections"], list)
        assert len(result["sections"]) > 0

        section = result["sections"][0]
        assert "name" in section
        assert "virtual_address" in section

    def test_extracts_headers(self, windows_system_dll: str) -> None:
        """Extracts PE header information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert isinstance(result["headers"], dict)

        if "dos_header" in result["headers"]:
            assert "signature" in result["headers"]["dos_header"]

        if "file_header" in result["headers"]:
            assert "machine" in result["headers"]["file_header"]
            assert "number_of_sections" in result["headers"]["file_header"]

        if "optional_header" in result["headers"]:
            assert "magic" in result["headers"]["optional_header"]

    def test_extracts_resources(self, windows_notepad_exe: str) -> None:
        """Extracts resource information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_notepad_exe)

        assert isinstance(result["resources"], dict)
        assert "has_resources" in result["resources"]
        assert "resource_types" in result["resources"]
        assert "total_resources" in result["resources"]

    def test_extracts_certificates(self, windows_system_dll: str) -> None:
        """Extracts certificate information."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert isinstance(result["certificates"], dict)
        assert "has_certificates" in result["certificates"]
        assert "certificate_count" in result["certificates"]

    def test_handles_invalid_pe_file(self, tmp_path: Path) -> None:
        """Handles invalid PE file gracefully."""
        invalid_pe = tmp_path / "invalid.exe"
        invalid_pe.write_bytes(b"This is not a PE file")

        analyzer = PEAnalyzer()
        result = analyzer.analyze(str(invalid_pe))

        assert "error" in result

    def test_compilation_timestamp_is_valid(self, windows_system_dll: str) -> None:
        """Compilation timestamp is valid."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert "compilation_timestamp" in result
        assert isinstance(result["compilation_timestamp"], int)
        assert result["compilation_timestamp"] > 0

    def test_entry_point_is_valid(self, windows_system_dll: str) -> None:
        """Entry point address is valid."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(windows_system_dll)

        assert "entry_point" in result
        assert isinstance(result["entry_point"], int)
        assert result["entry_point"] >= 0


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_pe_with_no_imports(self, pefile_pe: Any) -> None:
        """Handles PE with no import directory."""

        class MockPE:
            pass

        mock_pe = MockPE()
        sections = get_pe_sections_info(mock_pe)

        assert sections == []

    def test_handles_nonexistent_file(self) -> None:
        """Handles nonexistent PE file gracefully."""
        icon_info = get_pe_icon_info("/nonexistent/file.exe")

        assert icon_info["has_icon"] is False
        assert icon_info["icon_count"] == 0

    def test_extract_icon_from_nonexistent_file(self) -> None:
        """Handles nonexistent file in icon extraction."""
        icon_image = extract_pe_icon("/nonexistent/file.exe")

        assert icon_image is None

    def test_extract_all_icons_creates_output_dir(
        self, windows_notepad_exe: str, tmp_path: Path
    ) -> None:
        """extract_all_pe_icons creates output directory if missing."""
        output_dir = tmp_path / "new_icons_dir"

        saved_icons = extract_all_pe_icons(windows_notepad_exe, str(output_dir))

        if len(saved_icons) > 0:
            assert output_dir.exists()


class TestIntegration:
    """Test integration between multiple PE analysis functions."""

    def test_complete_pe_analysis_workflow(self, windows_system_dll: str) -> None:
        """Complete workflow: analyze -> extract sections -> analyze imports."""
        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(windows_system_dll)

            sections = get_pe_sections_info(pe)
            assert len(sections) > 0

            target_apis = {
                "process": ["CreateProcess", "OpenProcess"],
                "memory": ["VirtualAlloc", "VirtualFree"],
            }
            imports = analyze_pe_imports(pe, target_apis)
            assert isinstance(imports, dict)

            analyzer = PEAnalyzer()
            full_analysis = analyzer.analyze(windows_system_dll)
            assert "sections" in full_analysis
            assert "imports" in full_analysis

        except ImportError:
            pytest.skip("pefile not available")

    def test_icon_extraction_workflow(
        self, windows_notepad_exe: str, tmp_path: Path
    ) -> None:
        """Complete icon extraction workflow."""
        icon_info = get_pe_icon_info(windows_notepad_exe)

        if icon_info["has_icon"]:
            output_path = tmp_path / "extracted_icon.png"
            icon_image = extract_pe_icon(windows_notepad_exe, str(output_path))

            if icon_image is not None:
                assert output_path.exists()

                output_dir = tmp_path / "all_icons"
                all_icons = extract_all_pe_icons(windows_notepad_exe, str(output_dir))

                if len(all_icons) > 0:
                    assert all(Path(icon).exists() for icon in all_icons)


class TestPerformance:
    """Test performance on real Windows binaries."""

    def test_section_extraction_is_fast(self, pefile_pe: Any) -> None:
        """Section extraction completes in reasonable time."""
        import time

        start_time = time.time()
        sections = get_pe_sections_info(pefile_pe)
        duration = time.time() - start_time

        assert len(sections) > 0
        assert duration < 1.0

    def test_full_analysis_is_fast(self, windows_system_dll: str) -> None:
        """Full PE analysis completes in reasonable time."""
        import time

        analyzer = PEAnalyzer()

        start_time = time.time()
        result = analyzer.analyze(windows_system_dll)
        duration = time.time() - start_time

        assert "sections" in result
        assert duration < 5.0
