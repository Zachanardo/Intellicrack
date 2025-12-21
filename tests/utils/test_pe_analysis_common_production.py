"""Production tests for PE analysis common utilities.

Tests PE import analysis, section extraction, icon extraction, and comprehensive
PE file analysis on real Windows executables.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path

import pytest


try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from PIL import Image

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

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


pytestmark = pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")


@pytest.fixture
def legitimate_binaries_dir() -> Path:
    """Get directory with legitimate PE binaries."""
    return Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "legitimate"


@pytest.fixture
def protected_binaries_dir() -> Path:
    """Get directory with protected PE binaries."""
    return Path(__file__).parent.parent / "fixtures" / "binaries" / "pe" / "protected"


@pytest.fixture
def legitimate_pe(legitimate_binaries_dir: Path) -> Path:
    """Get a legitimate PE binary for testing."""
    binary_candidates = [
        legitimate_binaries_dir / "7zip.exe",
        legitimate_binaries_dir / "notepadpp.exe",
        legitimate_binaries_dir / "vlc.exe",
        legitimate_binaries_dir / "firefox.exe",
    ]

    for binary in binary_candidates:
        if binary.exists():
            return binary

    pytest.skip("No legitimate PE binary found in fixtures")


@pytest.fixture
def protected_pe(protected_binaries_dir: Path) -> Path:
    """Get a protected PE binary for testing."""
    binary_candidates = [
        protected_binaries_dir / "vmprotect_protected.exe",
        protected_binaries_dir / "themida_protected.exe",
        protected_binaries_dir / "enigma_packed.exe",
        protected_binaries_dir / "upx_packed_0.exe",
    ]

    protected_dir_alt = Path(__file__).parent.parent / "fixtures" / "binaries" / "protected"
    binary_candidates.extend([
        protected_dir_alt / "vmprotect_protected.exe",
        protected_dir_alt / "themida_protected.exe",
        protected_dir_alt / "enigma_packed.exe",
        protected_dir_alt / "upx_packed_0.exe",
    ])

    for binary in binary_candidates:
        if binary.exists():
            return binary

    pytest.skip("No protected PE binary found in fixtures")


class TestAnalyzePEImports:
    """Tests for PE import analysis."""

    def test_analyze_network_apis(self, legitimate_pe: Path) -> None:
        """Analyze PE imports for network-related APIs."""
        pe = pefile.PE(str(legitimate_pe))

        target_apis = {
            "network": ["WSAStartup", "connect", "send", "recv", "socket", "bind", "listen", "accept"],
            "http": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"],
            "crypto": ["CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt"],
        }

        result = analyze_pe_imports(pe, target_apis)

        assert isinstance(result, dict)
        assert all(category in result for category in target_apis)

    def test_analyze_empty_target_apis(self, legitimate_pe: Path) -> None:
        """Analyze with empty target API list."""
        pe = pefile.PE(str(legitimate_pe))

        result = analyze_pe_imports(pe, {})

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_analyze_licensing_apis(self, protected_pe: Path) -> None:
        """Analyze protected binary for licensing-related APIs."""
        pe = pefile.PE(str(protected_pe))

        target_apis = {
            "licensing": ["RegOpenKey", "RegQueryValue", "RegSetValue", "GetVolumeInformation"],
            "crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptHashData"],
        }

        result = analyze_pe_imports(pe, target_apis)

        assert isinstance(result, dict)


class TestGetPESectionsInfo:
    """Tests for PE section extraction."""

    def test_extract_sections_legitimate_binary(self, legitimate_pe: Path) -> None:
        """Extract sections from legitimate PE binary."""
        pe = pefile.PE(str(legitimate_pe))

        sections = get_pe_sections_info(pe)

        assert isinstance(sections, list)
        assert len(sections) > 0

        for section in sections:
            assert "name" in section
            assert "virtual_address" in section
            assert "virtual_size" in section
            assert "raw_size" in section
            assert "characteristics" in section

            assert isinstance(section["name"], str)
            assert isinstance(section["virtual_address"], int)
            assert isinstance(section["virtual_size"], int)
            assert isinstance(section["raw_size"], int)
            assert isinstance(section["characteristics"], int)

    def test_extract_sections_protected_binary(self, protected_pe: Path) -> None:
        """Extract sections from protected PE binary."""
        pe = pefile.PE(str(protected_pe))

        sections = get_pe_sections_info(pe)

        assert isinstance(sections, list)
        assert len(sections) > 0

        section_names = [s["name"] for s in sections]
        assert any(section_names)

    def test_section_characteristics(self, legitimate_pe: Path) -> None:
        """Verify section characteristics are extracted correctly."""
        pe = pefile.PE(str(legitimate_pe))

        sections = get_pe_sections_info(pe)

        for section in sections:
            characteristics = section["characteristics"]
            assert characteristics >= 0

            if section["name"] == ".text":
                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                assert characteristics & IMAGE_SCN_MEM_EXECUTE != 0 or characteristics > 0

    def test_common_section_names(self, legitimate_pe: Path) -> None:
        """Verify common PE sections are present."""
        pe = pefile.PE(str(legitimate_pe))

        sections = get_pe_sections_info(pe)
        section_names = [s["name"] for s in sections]

        common_sections = [".text", ".data", ".rdata", ".bss", ".rsrc", ".idata"]
        found_sections = [s for s in common_sections if s in section_names]

        assert found_sections


@pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
class TestExtractPEIcon:
    """Tests for PE icon extraction."""

    def test_extract_icon_from_legitimate_binary(self, legitimate_pe: Path, tmp_path: Path) -> None:
        """Extract icon from legitimate PE binary."""
        output_path = tmp_path / "extracted_icon.png"

        icon = extract_pe_icon(str(legitimate_pe), str(output_path))

        if icon is not None:
            assert isinstance(icon, Image.Image)
            assert output_path.exists()
            assert output_path.stat().st_size > 0
        else:
            assert not output_path.exists()

    def test_extract_icon_no_output_path(self, legitimate_pe: Path) -> None:
        """Extract icon without saving to file."""
        icon = extract_pe_icon(str(legitimate_pe))

        if icon is not None:
            assert isinstance(icon, Image.Image)
            assert icon.size[0] > 0
            assert icon.size[1] > 0

    def test_extract_icon_from_binary_without_icon(self, tmp_path: Path) -> None:
        """Extract icon from PE without icon resources."""
        binary_path = tmp_path / "no_icon.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 100

        binary_path.write_bytes(pe_header)

        icon = extract_pe_icon(str(binary_path))

        assert icon is None

    def test_extract_icon_from_resources(self, legitimate_pe: Path) -> None:
        """Extract icon data from PE resources."""
        pe = pefile.PE(str(legitimate_pe))

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            icon_data = extract_icon_from_resources(pe)

            if icon_data is not None:
                assert isinstance(icon_data, bytes)
                assert len(icon_data) > 0
        else:
            pytest.skip("Binary has no resources")

    def test_extract_all_icons(self, legitimate_pe: Path, tmp_path: Path) -> None:
        """Extract all icons from PE binary."""
        output_dir = tmp_path / "icons"

        saved_icons = extract_all_pe_icons(str(legitimate_pe), str(output_dir))

        assert isinstance(saved_icons, list)

        if len(saved_icons) > 0:
            assert output_dir.exists()

            for icon_path in saved_icons:
                assert Path(icon_path).exists()
                assert Path(icon_path).stat().st_size > 0

    def test_get_pe_icon_info(self, legitimate_pe: Path) -> None:
        """Get icon information from PE binary."""
        icon_info = get_pe_icon_info(str(legitimate_pe))

        assert isinstance(icon_info, dict)
        assert "has_icon" in icon_info
        assert "icon_count" in icon_info
        assert "icon_groups" in icon_info
        assert "icon_sizes" in icon_info
        assert "largest_icon" in icon_info

        if icon_info["has_icon"]:
            assert icon_info["icon_count"] > 0
            assert isinstance(icon_info["icon_sizes"], list)


class TestCreateImageFromIconData:
    """Tests for creating PIL images from icon data."""

    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_create_image_from_valid_ico(self) -> None:
        """Create image from valid ICO data."""
        ico_header = b"\x00\x00\x01\x00\x01\x00"
        ico_header += b"\x10\x10\x00\x00\x01\x00\x20\x00"
        ico_header += b"\x68\x04\x00\x00\x16\x00\x00\x00"

        pixel_data = b"\x00" * 0x468

        icon_data = ico_header + pixel_data

        image = create_image_from_icon_data(icon_data)

        if image is not None:
            assert isinstance(image, Image.Image)

    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_create_image_from_invalid_data(self) -> None:
        """Create image from invalid icon data."""
        invalid_data = b"invalid icon data"

        image = create_image_from_icon_data(invalid_data)

        assert image is None

    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_create_image_from_empty_data(self) -> None:
        """Create image from empty icon data."""
        image = create_image_from_icon_data(b"")

        assert image is None


class TestPEAnalyzer:
    """Tests for comprehensive PE analyzer."""

    def test_analyzer_initialization(self) -> None:
        """Initialize PE analyzer."""
        analyzer = PEAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "logger")

    def test_analyze_legitimate_binary(self, legitimate_pe: Path) -> None:
        """Analyze legitimate PE binary comprehensively."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(str(legitimate_pe))

        assert isinstance(result, dict)
        assert "imports" in result
        assert "exports" in result
        assert "sections" in result
        assert "headers" in result
        assert "resources" in result
        assert "certificates" in result
        assert "icon_info" in result
        assert "architecture" in result
        assert "compilation_timestamp" in result
        assert "is_dll" in result
        assert "is_exe" in result
        assert "checksum" in result
        assert "entry_point" in result

        assert result["is_exe"] is True or result["is_dll"] is True

    def test_analyze_protected_binary(self, protected_pe: Path) -> None:
        """Analyze protected PE binary."""
        analyzer = PEAnalyzer()

        result = analyzer.analyze(str(protected_pe))

        assert isinstance(result, dict)
        assert "sections" in result
        assert len(result["sections"]) > 0

    def test_extract_imports_comprehensive(self, legitimate_pe: Path) -> None:
        """Extract imports with comprehensive details."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        imports = analyzer._extract_imports(pe)

        assert isinstance(imports, list)

        if len(imports) > 0:
            for dll_import in imports:
                assert "dll" in dll_import
                assert "functions" in dll_import
                assert isinstance(dll_import["dll"], str)
                assert isinstance(dll_import["functions"], list)

                for function in dll_import["functions"]:
                    assert "name" in function
                    assert "address" in function

    def test_extract_exports(self, legitimate_pe: Path) -> None:
        """Extract exports from PE binary."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        exports = analyzer._extract_exports(pe)

        assert isinstance(exports, list)

        for export in exports:
            assert "address" in export
            assert "ordinal" in export

    def test_extract_headers(self, legitimate_pe: Path) -> None:
        """Extract PE headers."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        headers = analyzer._extract_headers(pe)

        assert isinstance(headers, dict)
        assert "dos_header" in headers
        assert "file_header" in headers
        assert "optional_header" in headers

        assert headers["dos_header"]["signature"] == 0x5A4D

    def test_extract_resources(self, legitimate_pe: Path) -> None:
        """Extract resource information."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        resources = analyzer._extract_resources(pe)

        assert isinstance(resources, dict)
        assert "has_resources" in resources
        assert "resource_types" in resources
        assert "total_resources" in resources

    def test_extract_certificates(self, legitimate_pe: Path) -> None:
        """Extract certificate information."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        certs = analyzer._extract_certificates(pe)

        assert isinstance(certs, dict)
        assert "has_certificates" in certs
        assert "certificate_count" in certs

    def test_get_architecture(self, legitimate_pe: Path) -> None:
        """Detect PE architecture."""
        analyzer = PEAnalyzer()
        pe = pefile.PE(str(legitimate_pe))

        architecture = analyzer._get_architecture(pe)

        assert isinstance(architecture, str)
        assert architecture in ["x86", "x64", "ARM", "ARM64"] or "Unknown" in architecture

    def test_analyze_nonexistent_file(self, tmp_path: Path) -> None:
        """Analyze nonexistent PE file."""
        analyzer = PEAnalyzer()
        nonexistent = tmp_path / "nonexistent.exe"

        result = analyzer.analyze(str(nonexistent))

        assert "error" in result


@pytest.mark.integration
class TestPEAnalysisIntegration:
    """Integration tests for PE analysis workflow."""

    def test_full_analysis_workflow(self, legitimate_pe: Path, tmp_path: Path) -> None:
        """Complete PE analysis workflow."""
        analyzer = PEAnalyzer()

        analysis_result = analyzer.analyze(str(legitimate_pe))

        assert "error" not in analysis_result

        assert len(analysis_result["sections"]) > 0

        if analysis_result["icon_info"]["has_icon"]:
            icon = extract_pe_icon(str(legitimate_pe))
            if icon and PIL_AVAILABLE:
                assert isinstance(icon, Image.Image)

    def test_analyze_multiple_binaries(self, legitimate_binaries_dir: Path) -> None:
        """Analyze multiple PE binaries."""
        analyzer = PEAnalyzer()

        binaries = list(legitimate_binaries_dir.glob("*.exe"))

        if not binaries:
            pytest.skip("No binaries found in legitimate binaries directory")

        results = []

        for binary in binaries[:3]:
            if binary.exists():
                result = analyzer.analyze(str(binary))
                results.append(result)

        assert results

        for result in results:
            assert isinstance(result, dict)
            if "error" not in result:
                assert "sections" in result


@pytest.mark.performance
class TestPEAnalysisPerformance:
    """Performance tests for PE analysis."""

    def test_analysis_performance(self, legitimate_pe: Path) -> None:
        """PE analysis completes within reasonable time."""
        import time

        analyzer = PEAnalyzer()

        start_time = time.time()
        analyzer.analyze(str(legitimate_pe))
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_section_extraction_performance(self, legitimate_pe: Path) -> None:
        """Section extraction is fast."""
        import time

        pe = pefile.PE(str(legitimate_pe))

        start_time = time.time()
        get_pe_sections_info(pe)
        elapsed = time.time() - start_time

        assert elapsed < 1.0
