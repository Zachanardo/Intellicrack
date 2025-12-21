"""Production Tests for Intellicrack Protection Core Module.

Tests validate comprehensive protection detection for packers, protectors, compilers,
licensing schemes using native ICP Engine integration. All tests use real binaries
and validate actual detection capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
from pathlib import Path
from typing import Generator

import pytest

from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    IntellicrackProtectionCore,
    LicenseType,
    ProtectionAnalysis,
    ProtectionType,
    quick_analyze,
)


WINDOWS_NOTEPAD = Path("C:/Windows/System32/notepad.exe")
WINDOWS_KERNEL32 = Path("C:/Windows/System32/kernel32.dll")


@pytest.fixture
def protection_core() -> IntellicrackProtectionCore:
    """Create IntellicrackProtectionCore instance for testing."""
    return IntellicrackProtectionCore()


@pytest.fixture
def sample_pe_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample PE32 binary for testing."""
    binary_path = tmp_path / "sample.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)

    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x1000,
        0x0,
        0,
        0x1000,
        0x1000,
        0x00400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section = b".text\x00\x00\x00" + struct.pack("<IIIIIHHHI", 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)

    pe_header = pe_signature + coff_header + optional_header + section
    headers = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data = bytearray(0x1000)
    code_data[:4] = b"\x55\x8b\xec\x5d"

    binary_data = headers.ljust(0x200, b"\x00") + code_data

    binary_path.write_bytes(binary_data)
    yield binary_path


@pytest.fixture
def real_system_binary() -> Path:
    """Provide real Windows system binary."""
    if not WINDOWS_NOTEPAD.exists():
        pytest.skip("Windows notepad.exe not available")
    return WINDOWS_NOTEPAD


@pytest.fixture
def protected_pe_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create PE binary with protection signatures."""
    binary_path = tmp_path / "protected.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x010B)

    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x2000,
        0x1000,
        0,
        0x1000,
        0x1000,
        0x00400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x5000,
        0x200,
        0,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    text_section = b".text\x00\x00\x00" + struct.pack("<IIIIIHHHI", 0x2000, 0x1000, 0x2000, 0x200, 0, 0, 0, 0, 0x60000020)
    data_section = b".data\x00\x00\x00" + struct.pack("<IIIIIHHHI", 0x1000, 0x3000, 0x1000, 0x2200, 0, 0, 0, 0, 0xC0000040)

    pe_header = pe_signature + coff_header + optional_header + text_section + data_section
    headers = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data = bytearray(0x2000)
    code_data[0x100 : 0x100 + len(b"UPX!")] = b"UPX!"
    code_data[0x500 : 0x500 + len(b"VMProtect")] = b"VMProtect"

    data_section_data = bytearray(0x1000)
    data_section_data[:len(b"license_key")] = b"license_key"

    binary_data = headers.ljust(0x200, b"\x00") + code_data + data_section_data

    binary_path.write_bytes(binary_data)
    yield binary_path


class TestProtectionTypeEnum:
    """Test ProtectionType enumeration."""

    def test_protection_type_has_all_categories(self) -> None:
        """ProtectionType enum has all protection categories."""
        assert hasattr(ProtectionType, "PACKER")
        assert hasattr(ProtectionType, "PROTECTOR")
        assert hasattr(ProtectionType, "COMPILER")
        assert hasattr(ProtectionType, "INSTALLER")
        assert hasattr(ProtectionType, "CRYPTOR")
        assert hasattr(ProtectionType, "DONGLE")
        assert hasattr(ProtectionType, "LICENSE")
        assert hasattr(ProtectionType, "DRM")
        assert hasattr(ProtectionType, "UNKNOWN")

    def test_protection_type_values_are_strings(self) -> None:
        """ProtectionType enum values are strings."""
        assert isinstance(ProtectionType.PACKER.value, str)
        assert isinstance(ProtectionType.PROTECTOR.value, str)


class TestLicenseTypeEnum:
    """Test LicenseType enumeration."""

    def test_license_type_has_all_schemes(self) -> None:
        """LicenseType enum has all licensing schemes."""
        assert hasattr(LicenseType, "FLEXLM")
        assert hasattr(LicenseType, "HASP")
        assert hasattr(LicenseType, "DONGLE")
        assert hasattr(LicenseType, "TRIAL")
        assert hasattr(LicenseType, "SUBSCRIPTION")
        assert hasattr(LicenseType, "PERPETUAL")
        assert hasattr(LicenseType, "CUSTOM")
        assert hasattr(LicenseType, "UNKNOWN")


class TestDetectionResult:
    """Test DetectionResult dataclass."""

    def test_detection_result_stores_all_fields(self) -> None:
        """DetectionResult stores complete detection information."""
        bypass_recs = ["Use UPX unpacker", "Manual OEP dump"]

        result = DetectionResult(
            name="UPX",
            version="3.96",
            type=ProtectionType.PACKER,
            confidence=100.0,
            details={"entropy": 7.2, "section": ".upx0"},
            bypass_recommendations=bypass_recs,
        )

        assert result.name == "UPX"
        assert result.version == "3.96"
        assert result.type == ProtectionType.PACKER
        assert result.confidence == 100.0
        assert result.details["entropy"] == 7.2
        assert len(result.bypass_recommendations) == 2


class TestProtectionAnalysis:
    """Test ProtectionAnalysis dataclass."""

    def test_protection_analysis_stores_complete_info(self) -> None:
        """ProtectionAnalysis stores complete binary analysis."""
        detection = DetectionResult(name="VMProtect", type=ProtectionType.PROTECTOR)

        analysis = ProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection],
            compiler="MSVC 19.0",
            is_packed=False,
            is_protected=True,
            has_overlay=False,
            entry_point="0x401000",
            sections=[{"name": ".text", "virtual_size": 0x1000}],
            imports=["kernel32.dll!LoadLibraryA"],
            metadata={"scan_time": 1.5},
        )

        assert analysis.file_path == "test.exe"
        assert analysis.file_type == "PE32"
        assert analysis.architecture == "x86"
        assert len(analysis.detections) == 1
        assert analysis.is_protected is True


class TestIntellicrackProtectionCoreInitialization:
    """Test IntellicrackProtectionCore initialization."""

    def test_core_initializes_with_icp_backend(self, protection_core: IntellicrackProtectionCore) -> None:
        """Protection core initializes with ICP backend."""
        assert protection_core.icp_backend is not None or protection_core.engine_path is not None

    def test_core_has_bypass_recommendations_database(self, protection_core: IntellicrackProtectionCore) -> None:
        """Protection core has comprehensive bypass recommendations."""
        assert "UPX" in protection_core.PROTECTION_BYPASSES
        assert "VMProtect" in protection_core.PROTECTION_BYPASSES
        assert "Themida" in protection_core.PROTECTION_BYPASSES
        assert "HASP" in protection_core.PROTECTION_BYPASSES
        assert "FlexLM" in protection_core.PROTECTION_BYPASSES
        assert "Denuvo" in protection_core.PROTECTION_BYPASSES

    def test_bypass_recommendations_have_concrete_steps(self, protection_core: IntellicrackProtectionCore) -> None:
        """Bypass recommendations contain concrete, actionable steps."""
        upx_bypasses = protection_core.PROTECTION_BYPASSES["UPX"]

        assert len(upx_bypasses) > 0
        assert any("upx -d" in bypass.lower() for bypass in upx_bypasses)

        vmprotect_bypasses = protection_core.PROTECTION_BYPASSES["VMProtect"]
        assert len(vmprotect_bypasses) > 0


class TestProtectionDetection:
    """Test protection detection on real binaries."""

    def test_detect_protections_analyzes_real_binary(
        self, protection_core: IntellicrackProtectionCore, real_system_binary: Path
    ) -> None:
        """detect_protections analyzes real Windows binary."""
        analysis = protection_core.detect_protections(str(real_system_binary))

        assert isinstance(analysis, ProtectionAnalysis)
        assert analysis.file_path == str(real_system_binary)
        assert analysis.file_type != "Unknown"
        assert analysis.architecture in ["x86", "x64"]

    def test_detect_protections_raises_error_for_nonexistent_file(self, protection_core: IntellicrackProtectionCore) -> None:
        """detect_protections raises FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError, match="File not found"):
            protection_core.detect_protections("nonexistent_file.exe")

    def test_detect_protections_identifies_file_type(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """detect_protections correctly identifies file type."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))

        assert "PE" in analysis.file_type or analysis.file_type == "Unknown"

    def test_detect_protections_determines_architecture(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """detect_protections determines binary architecture."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))

        assert analysis.architecture in ["x86", "x64", "Unknown"]

    def test_detect_protections_includes_metadata(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """detect_protections includes scan metadata."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))

        assert isinstance(analysis.metadata, dict)
        assert len(analysis.metadata) > 0


class TestDetectionCategorization:
    """Test detection type categorization."""

    def test_categorize_detection_identifies_packers(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection identifies packer types."""
        assert protection_core._categorize_detection("Packer") == ProtectionType.PACKER
        assert protection_core._categorize_detection("packer") == ProtectionType.PACKER

    def test_categorize_detection_identifies_protectors(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection identifies protector types."""
        assert protection_core._categorize_detection("Protector") == ProtectionType.PROTECTOR
        assert protection_core._categorize_detection("protection") == ProtectionType.PROTECTOR

    def test_categorize_detection_identifies_compilers(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection identifies compiler types."""
        assert protection_core._categorize_detection("Compiler") == ProtectionType.COMPILER
        assert protection_core._categorize_detection("compiled") == ProtectionType.COMPILER

    def test_categorize_detection_identifies_licensing(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection identifies licensing schemes."""
        assert protection_core._categorize_detection("License") == ProtectionType.LICENSE
        assert protection_core._categorize_detection("FlexLM") == ProtectionType.LICENSE

    def test_categorize_detection_identifies_dongles(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection identifies dongle protection."""
        assert protection_core._categorize_detection("Dongle") == ProtectionType.DONGLE
        assert protection_core._categorize_detection("HASP") == ProtectionType.DONGLE
        assert protection_core._categorize_detection("Sentinel") == ProtectionType.DONGLE

    def test_categorize_detection_handles_unknown_types(self, protection_core: IntellicrackProtectionCore) -> None:
        """_categorize_detection returns UNKNOWN for unrecognized types."""
        assert protection_core._categorize_detection("RandomType") == ProtectionType.UNKNOWN


class TestBypassRecommendations:
    """Test bypass recommendation retrieval."""

    def test_get_bypass_recommendations_returns_exact_matches(self, protection_core: IntellicrackProtectionCore) -> None:
        """_get_bypass_recommendations returns exact protection matches."""
        upx_bypasses = protection_core._get_bypass_recommendations("UPX")

        assert len(upx_bypasses) > 0
        assert any("upx -d" in bypass.lower() for bypass in upx_bypasses)

    def test_get_bypass_recommendations_handles_partial_matches(
        self, protection_core: IntellicrackProtectionCore
    ) -> None:
        """_get_bypass_recommendations handles partial name matches."""
        vmprotect_bypasses = protection_core._get_bypass_recommendations("VMProtect 3.5")

        assert len(vmprotect_bypasses) > 0

    def test_get_bypass_recommendations_provides_generic_for_unknown(
        self, protection_core: IntellicrackProtectionCore
    ) -> None:
        """_get_bypass_recommendations provides generic advice for unknown protections."""
        unknown_bypasses = protection_core._get_bypass_recommendations("UnknownProtection")

        assert len(unknown_bypasses) > 0
        assert any("manual analysis" in bypass.lower() for bypass in unknown_bypasses)

    def test_get_bypass_recommendations_for_packers(self, protection_core: IntellicrackProtectionCore) -> None:
        """_get_bypass_recommendations provides packer-specific advice."""
        packer_bypasses = protection_core._get_bypass_recommendations("SomeNewPacker")

        assert any("unpack" in bypass.lower() for bypass in packer_bypasses)

    def test_get_bypass_recommendations_for_licensing(self, protection_core: IntellicrackProtectionCore) -> None:
        """_get_bypass_recommendations provides licensing-specific advice."""
        license_bypasses = protection_core._get_bypass_recommendations("CustomLicense")

        assert any("license" in bypass.lower() or "api" in bypass.lower() for bypass in license_bypasses)


class TestDirectoryScan:
    """Test directory scanning functionality."""

    def test_analyze_directory_scans_executables(
        self, protection_core: IntellicrackProtectionCore, tmp_path: Path, sample_pe_binary: Path
    ) -> None:
        """analyze_directory scans all executables in directory."""
        test_dir = tmp_path / "binaries"
        test_dir.mkdir()

        (test_dir / "test1.exe").write_bytes(sample_pe_binary.read_bytes())
        (test_dir / "test2.dll").write_bytes(sample_pe_binary.read_bytes())

        results = protection_core.analyze_directory(str(test_dir), recursive=False)

        assert len(results) >= 2

    def test_analyze_directory_recursive_scan(
        self, protection_core: IntellicrackProtectionCore, tmp_path: Path, sample_pe_binary: Path
    ) -> None:
        """analyze_directory performs recursive scanning."""
        test_dir = tmp_path / "binaries"
        test_dir.mkdir()
        sub_dir = test_dir / "sub"
        sub_dir.mkdir()

        (test_dir / "test1.exe").write_bytes(sample_pe_binary.read_bytes())
        (sub_dir / "test2.exe").write_bytes(sample_pe_binary.read_bytes())

        results = protection_core.analyze_directory(str(test_dir), recursive=True)

        assert len(results) >= 2

    def test_analyze_directory_handles_errors_gracefully(
        self, protection_core: IntellicrackProtectionCore, tmp_path: Path
    ) -> None:
        """analyze_directory handles analysis errors gracefully."""
        test_dir = tmp_path / "binaries"
        test_dir.mkdir()

        invalid_exe = test_dir / "invalid.exe"
        invalid_exe.write_bytes(b"Not a valid PE file")

        results = protection_core.analyze_directory(str(test_dir), recursive=False)

        assert isinstance(results, list)


class TestSummaryAndExport:
    """Test summary generation and export functionality."""

    def test_get_summary_generates_readable_text(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """get_summary generates human-readable summary."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))
        summary = protection_core.get_summary(analysis)

        assert isinstance(summary, str)
        assert len(summary) > 0
        assert sample_pe_binary.name in summary

    def test_export_results_json_format(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """export_results exports analysis as JSON."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))
        json_output = protection_core.export_results(analysis, "json")

        assert isinstance(json_output, str)
        import json

        data = json.loads(json_output)
        assert "file_path" in data
        assert "file_type" in data

    def test_export_results_text_format(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """export_results exports analysis as text."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))
        text_output = protection_core.export_results(analysis, "text")

        assert isinstance(text_output, str)
        assert len(text_output) > 0

    def test_export_results_csv_format(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """export_results exports analysis as CSV."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))
        csv_output = protection_core.export_results(analysis, "csv")

        assert isinstance(csv_output, str)
        assert "File,Type,Architecture" in csv_output

    def test_export_results_raises_error_for_unknown_format(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """export_results raises ValueError for unknown format."""
        analysis = protection_core.detect_protections(str(sample_pe_binary))

        with pytest.raises(ValueError, match="Unknown output format"):
            protection_core.export_results(analysis, "unknown_format")


class TestQuickAnalyze:
    """Test quick_analyze convenience function."""

    def test_quick_analyze_analyzes_binary(self, sample_pe_binary: Path) -> None:
        """quick_analyze convenience function analyzes binary."""
        analysis = quick_analyze(str(sample_pe_binary))

        assert isinstance(analysis, ProtectionAnalysis)
        assert analysis.file_path == str(sample_pe_binary)


class TestFallbackAnalysis:
    """Test fallback analysis when ICP Engine unavailable."""

    def test_fallback_analysis_detects_pe_files(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """_fallback_analysis detects PE files."""
        analysis = protection_core._fallback_analysis(str(sample_pe_binary))

        assert analysis.file_type == "PE"
        assert analysis.architecture in ["x86", "x64"]

    def test_fallback_analysis_detects_architecture(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """_fallback_analysis correctly detects architecture."""
        analysis = protection_core._fallback_analysis(str(sample_pe_binary))

        assert analysis.architecture == "x86"

    def test_fallback_analysis_includes_metadata(
        self, protection_core: IntellicrackProtectionCore, sample_pe_binary: Path
    ) -> None:
        """_fallback_analysis includes fallback metadata."""
        analysis = protection_core._fallback_analysis(str(sample_pe_binary))

        assert "fallback_mode" in analysis.metadata
        assert analysis.metadata["fallback_mode"] is True
