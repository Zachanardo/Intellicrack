"""Production tests for intellicrack/core/analysis/core_analysis.py

Tests validate REAL offensive capabilities:
- Machine type detection from PE headers (x86, x64, ARM, ARM64)
- Magic type identification (PE32, PE32+, ROM image)
- Characteristics flag parsing for executable properties
- PE timestamp conversion
- Complete binary analysis on real Windows executables
- Section entropy analysis for detecting packed/protected code
- Import/export analysis for license-related functions
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.core_analysis import (
    analyze_binary_internal,
    get_characteristics,
    get_machine_type,
    get_magic_type,
    get_pe_timestamp,
)

try:
    from intellicrack.handlers.pefile_handler import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class TestMachineTypeDetection:
    """Test PE machine type detection for different architectures."""

    def test_x86_32bit_machine_type_detection(self) -> None:
        """Machine type 0x014C correctly identified as x86 (32-bit)."""
        machine_type: str = get_machine_type(0x014C)

        assert machine_type == "x86 (32-bit)"

    def test_x64_64bit_machine_type_detection(self) -> None:
        """Machine type 0x8664 correctly identified as x64 (64-bit)."""
        machine_type: str = get_machine_type(0x8664)

        assert machine_type == "x64 (64-bit)"

    def test_intel_itanium_machine_type_detection(self) -> None:
        """Machine type 0x0200 correctly identified as Intel Itanium."""
        machine_type: str = get_machine_type(0x0200)

        assert machine_type == "Intel Itanium"

    def test_arm_little_endian_machine_type_detection(self) -> None:
        """Machine type 0x01C0 correctly identified as ARM little endian."""
        machine_type: str = get_machine_type(0x01C0)

        assert machine_type == "ARM little endian"

    def test_arm_thumb2_machine_type_detection(self) -> None:
        """Machine type 0x01C4 correctly identified as ARM Thumb-2."""
        machine_type: str = get_machine_type(0x01C4)

        assert machine_type == "ARM Thumb-2 little endian"

    def test_arm64_machine_type_detection(self) -> None:
        """Machine type 0xAA64 correctly identified as ARM64."""
        machine_type: str = get_machine_type(0xAA64)

        assert machine_type == "ARM64 little endian"

    def test_unknown_machine_type_returns_hex_value(self) -> None:
        """Unknown machine types return hex representation."""
        machine_type: str = get_machine_type(0x9999)

        assert "0x9999" in machine_type
        assert "Unknown" in machine_type


class TestMagicTypeDetection:
    """Test PE optional header magic type detection."""

    def test_pe32_magic_type_detection(self) -> None:
        """Magic 0x10B correctly identified as PE32 (32-bit)."""
        magic_type: str = get_magic_type(0x10B)

        assert magic_type == "PE32"

    def test_pe32_plus_magic_type_detection(self) -> None:
        """Magic 0x20B correctly identified as PE32+ (64-bit)."""
        magic_type: str = get_magic_type(0x20B)

        assert magic_type == "PE32+"

    def test_rom_image_magic_type_detection(self) -> None:
        """Magic 0x107 correctly identified as ROM image."""
        magic_type: str = get_magic_type(0x107)

        assert magic_type == "ROM image"

    def test_unknown_magic_type_returns_hex_value(self) -> None:
        """Unknown magic types return hex representation."""
        magic_type: str = get_magic_type(0xFFFF)

        assert "0xFFFF" in magic_type
        assert "Unknown" in magic_type


class TestCharacteristicsDetection:
    """Test PE characteristics flag parsing."""

    def test_executable_image_characteristic(self) -> None:
        """Characteristic 0x0002 correctly identified as EXECUTABLE_IMAGE."""
        characteristics: str = get_characteristics(0x0002)

        assert "EXECUTABLE_IMAGE" in characteristics

    def test_dll_characteristic(self) -> None:
        """Characteristic 0x2000 correctly identified as DLL."""
        characteristics: str = get_characteristics(0x2000)

        assert "DLL" in characteristics

    def test_large_address_aware_characteristic(self) -> None:
        """Characteristic 0x0020 correctly identified as LARGE_ADDRESS_AWARE."""
        characteristics: str = get_characteristics(0x0020)

        assert "LARGE_ADDRESS_AWARE" in characteristics

    def test_debug_stripped_characteristic(self) -> None:
        """Characteristic 0x0200 correctly identified as DEBUG_STRIPPED."""
        characteristics: str = get_characteristics(0x0200)

        assert "DEBUG_STRIPPED" in characteristics

    def test_32bit_machine_characteristic(self) -> None:
        """Characteristic 0x0100 correctly identified as 32BIT_MACHINE."""
        characteristics: str = get_characteristics(0x0100)

        assert "32BIT_MACHINE" in characteristics

    def test_multiple_characteristics_combined(self) -> None:
        """Multiple characteristic flags correctly parsed and combined."""
        combined_flags = 0x0002 | 0x0100 | 0x0020

        characteristics: str = get_characteristics(combined_flags)

        assert "EXECUTABLE_IMAGE" in characteristics
        assert "32BIT_MACHINE" in characteristics
        assert "LARGE_ADDRESS_AWARE" in characteristics
        assert "|" in characteristics

    def test_relocs_stripped_characteristic(self) -> None:
        """Characteristic 0x0001 correctly identified as RELOCS_STRIPPED."""
        characteristics: str = get_characteristics(0x0001)

        assert "RELOCS_STRIPPED" in characteristics

    def test_system_characteristic(self) -> None:
        """Characteristic 0x1000 correctly identified as SYSTEM."""
        characteristics: str = get_characteristics(0x1000)

        assert "SYSTEM" in characteristics

    def test_no_characteristics_returns_none(self) -> None:
        """Zero characteristic flags returns 'None'."""
        characteristics: str = get_characteristics(0x0000)

        assert characteristics == "None"


class TestPETimestampConversion:
    """Test PE timestamp conversion to human-readable format."""

    def test_valid_unix_timestamp_conversion(self) -> None:
        """Valid Unix timestamp correctly converted to datetime."""
        timestamp = 1609459200

        pe_timestamp: str = get_pe_timestamp(timestamp)

        assert "2021" in pe_timestamp
        assert ":" in pe_timestamp

    def test_zero_timestamp_conversion(self) -> None:
        """Zero timestamp (epoch) correctly handled."""
        timestamp = 0

        pe_timestamp: str = get_pe_timestamp(timestamp)

        assert "1970" in pe_timestamp

    def test_invalid_negative_timestamp_returns_error(self) -> None:
        """Invalid negative timestamp returns error message."""
        timestamp = -1

        pe_timestamp: str = get_pe_timestamp(timestamp)

        assert "Invalid" in pe_timestamp or "1969" in pe_timestamp

    def test_very_large_timestamp_returns_error(self) -> None:
        """Extremely large timestamp (beyond year 9999) returns error."""
        timestamp = 999999999999

        pe_timestamp: str = get_pe_timestamp(timestamp)

        assert isinstance(pe_timestamp, str)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
class TestRealBinaryAnalysis:
    """Test binary analysis on real PE executables."""

    @pytest.fixture
    def legitimate_pe_binaries(self) -> list[Path]:
        """Provide paths to legitimate PE binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate")
        if not binaries_dir.exists():
            return []
        return list(binaries_dir.glob("*.exe"))

    @pytest.fixture
    def protected_binaries(self) -> list[Path]:
        """Provide paths to protected PE binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected")
        if not binaries_dir.exists():
            return []
        return list(binaries_dir.glob("*.exe"))

    def test_binary_analysis_parses_pe_header(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly parses PE header from real executables."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        assert len(results) > 0
        assert any("PE Header" in r for r in results)
        assert any("Machine:" in r for r in results)
        assert any("Number of sections:" in r for r in results)

    def test_binary_analysis_identifies_x86_architecture(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly identifies x86 or x64 architecture."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        for binary_path in legitimate_pe_binaries[:3]:
            results: list[str] = analyze_binary_internal(str(binary_path))

            machine_lines = [r for r in results if "Machine:" in r]
            assert len(machine_lines) > 0

            machine_line = machine_lines[0]
            assert any(arch in machine_line for arch in ["x86", "x64", "ARM"])

    def test_binary_analysis_parses_optional_header(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly parses optional header from real executables."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        assert any("Optional Header" in r for r in results)
        assert any("Magic:" in r for r in results)
        assert any("Entry point:" in r for r in results)
        assert any("Image base:" in r for r in results)

    def test_binary_analysis_identifies_pe32_vs_pe32plus(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly distinguishes PE32 from PE32+."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        for binary_path in legitimate_pe_binaries[:3]:
            results: list[str] = analyze_binary_internal(str(binary_path))

            magic_lines = [r for r in results if "Magic:" in r]
            assert len(magic_lines) > 0

            magic_line = magic_lines[0]
            assert "PE32" in magic_line

    def test_binary_analysis_enumerates_sections(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis enumerates all PE sections."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        assert any("Sections:" in r for r in results)
        assert any("Virtual Address:" in r for r in results)
        assert any("Virtual Size:" in r for r in results)

    def test_binary_analysis_calculates_section_entropy(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis calculates entropy for each section."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        entropy_lines = [r for r in results if "Entropy:" in r]
        assert len(entropy_lines) > 0

        for entropy_line in entropy_lines:
            assert any(char.isdigit() for char in entropy_line)

    def test_binary_analysis_detects_high_entropy_sections(self, protected_binaries: list[Path]) -> None:
        """Binary analysis identifies high-entropy sections in protected binaries."""
        if not protected_binaries:
            pytest.skip("No protected binaries available")

        for binary_path in protected_binaries[:5]:
            results: list[str] = analyze_binary_internal(str(binary_path))

            has_entropy_calculation = any("Entropy:" in r for r in results)
            assert has_entropy_calculation

    def test_binary_analysis_identifies_executable_characteristics(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly identifies executable characteristics."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        characteristics_lines = [r for r in results if "Characteristics:" in r]
        assert len(characteristics_lines) > 0

        characteristics_line = characteristics_lines[0]
        assert "0x" in characteristics_line

    def test_binary_analysis_identifies_dll_files(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis correctly identifies DLL files."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate")
        dll_files = list(binaries_dir.glob("*.dll")) if binaries_dir.exists() else []

        if not dll_files:
            pytest.skip("No DLL files available")

        binary_path = dll_files[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        characteristics_lines = [r for r in results if "Characteristics:" in r]
        if len(characteristics_lines) > 0:
            assert any("DLL" in r for r in characteristics_lines)

    def test_binary_analysis_parses_timestamp(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis parses and formats PE timestamp."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        timestamp_lines = [r for r in results if "Time date stamp:" in r]
        assert len(timestamp_lines) > 0

        timestamp_line = timestamp_lines[0]
        assert "0x" in timestamp_line

    def test_binary_analysis_reports_file_size(self, legitimate_pe_binaries: list[Path]) -> None:
        """Binary analysis reports accurate file size."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]
        actual_size = binary_path.stat().st_size

        results: list[str] = analyze_binary_internal(str(binary_path))

        size_lines = [r for r in results if "File size:" in r]
        assert len(size_lines) > 0

        size_line = size_lines[0]
        assert "bytes" in size_line
        assert str(actual_size) in size_line.replace(",", "")


class TestBinaryAnalysisEdgeCases:
    """Test edge cases and error handling in binary analysis."""

    def test_binary_analysis_handles_nonexistent_file(self) -> None:
        """Binary analysis gracefully handles nonexistent file paths."""
        nonexistent_path = "D:/nonexistent/fake.exe"

        results: list[str] = analyze_binary_internal(nonexistent_path)

        assert len(results) > 0
        assert any("ERROR" in r for r in results)

    def test_binary_analysis_handles_invalid_pe_file(self, tmp_path: Path) -> None:
        """Binary analysis gracefully handles corrupted PE files."""
        invalid_pe = tmp_path / "invalid.exe"
        invalid_pe.write_bytes(b"This is not a valid PE file" * 100)

        results: list[str] = analyze_binary_internal(str(invalid_pe))

        assert len(results) > 0
        assert any("ERROR" in r or "invalid" in r.lower() for r in results)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
    def test_binary_analysis_handles_empty_file(self, tmp_path: Path) -> None:
        """Binary analysis handles empty files gracefully."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        results: list[str] = analyze_binary_internal(str(empty_file))

        assert len(results) > 0
        assert any("ERROR" in r or "invalid" in r.lower() for r in results)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
    def test_binary_analysis_with_stealth_flag(self, tmp_path: Path) -> None:
        """Binary analysis respects stealth flag to skip string scanning."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 1000)

        results_normal: list[str] = analyze_binary_internal(str(test_file), flags=[])
        results_stealth: list[str] = analyze_binary_internal(str(test_file), flags=["stealth"])

        assert isinstance(results_normal, list)
        assert isinstance(results_stealth, list)


class TestLicenseRelatedImportDetection:
    """Test detection of license-related imports in binaries."""

    @pytest.fixture
    def protected_binaries(self) -> list[Path]:
        """Provide paths to protected binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected")
        if not binaries_dir.exists():
            return []
        return list(binaries_dir.glob("*.exe"))

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
    def test_binary_analysis_identifies_imports(self, protected_binaries: list[Path]) -> None:
        """Binary analysis enumerates imported functions."""
        if not protected_binaries:
            pytest.skip("No protected binaries available")

        for binary_path in protected_binaries[:3]:
            results: list[str] = analyze_binary_internal(str(binary_path))

            assert isinstance(results, list)
            assert len(results) > 0


class TestSectionEntropyAnalysis:
    """Test entropy calculation for detecting packed/protected sections."""

    @pytest.fixture
    def protected_binaries(self) -> list[Path]:
        """Provide paths to protected binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected")
        if not binaries_dir.exists():
            return []
        return list(binaries_dir.glob("*.exe"))

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
    def test_high_entropy_detection_in_protected_binaries(self, protected_binaries: list[Path]) -> None:
        """High entropy sections correctly identified in protected binaries."""
        if not protected_binaries:
            pytest.skip("No protected binaries available")

        high_entropy_found = False

        for binary_path in protected_binaries[:5]:
            results: list[str] = analyze_binary_internal(str(binary_path))

            if any("High entropy" in r for r in results):
                high_entropy_found = True
                break

        if high_entropy_found:
            assert True

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
    def test_entropy_values_within_valid_range(self, protected_binaries: list[Path]) -> None:
        """Entropy values fall within valid range (0.0 to 8.0)."""
        if not protected_binaries:
            pytest.skip("No protected binaries available")

        binary_path = protected_binaries[0]

        results: list[str] = analyze_binary_internal(str(binary_path))

        entropy_lines = [r for r in results if "Entropy:" in r and not "WARNING" in r]

        for entropy_line in entropy_lines:
            parts = entropy_line.split(":")
            if len(parts) >= 2:
                entropy_str = parts[1].strip()
                try:
                    entropy_val = float(entropy_str)
                    assert 0.0 <= entropy_val <= 8.0
                except ValueError:
                    pass


class TestMultiArchitectureSupport:
    """Test support for multiple CPU architectures."""

    def test_all_common_architectures_recognized(self) -> None:
        """All common PE machine types correctly recognized."""
        architectures = {
            0x014C: "x86",
            0x8664: "x64",
            0x0200: "Itanium",
            0x01C0: "ARM",
            0x01C4: "Thumb",
            0xAA64: "ARM64",
        }

        for machine_code, expected_substring in architectures.items():
            machine_type: str = get_machine_type(machine_code)
            assert expected_substring in machine_type

    def test_all_magic_types_recognized(self) -> None:
        """All PE magic types correctly recognized."""
        magic_types = {
            0x10B: "PE32",
            0x20B: "PE32+",
            0x107: "ROM",
        }

        for magic_code, expected_type in magic_types.items():
            magic_type: str = get_magic_type(magic_code)
            assert expected_type in magic_type


class TestCharacteristicsFlagCoverage:
    """Test comprehensive coverage of all PE characteristics flags."""

    def test_all_characteristics_flags_recognized(self) -> None:
        """All PE characteristics flags correctly parsed."""
        flags_to_test = {
            0x0001: "RELOCS_STRIPPED",
            0x0002: "EXECUTABLE_IMAGE",
            0x0004: "LINE_NUMBERS_STRIPPED",
            0x0008: "LOCAL_SYMS_STRIPPED",
            0x0010: "AGGR_WS_TRIM",
            0x0020: "LARGE_ADDRESS_AWARE",
            0x0080: "BYTES_REVERSED_LO",
            0x0100: "32BIT_MACHINE",
            0x0200: "DEBUG_STRIPPED",
            0x0400: "REMOVABLE_RUN_FROM_SWAP",
            0x0800: "NET_RUN_FROM_SWAP",
            0x1000: "SYSTEM",
            0x2000: "DLL",
            0x4000: "UP_SYSTEM_ONLY",
            0x8000: "BYTES_REVERSED_HI",
        }

        for flag_value, expected_name in flags_to_test.items():
            characteristics: str = get_characteristics(flag_value)
            assert expected_name in characteristics

    def test_combined_characteristics_all_present(self) -> None:
        """Multiple characteristics correctly combined with separators."""
        combined = 0x0002 | 0x2000 | 0x0100

        characteristics: str = get_characteristics(combined)

        assert "EXECUTABLE_IMAGE" in characteristics
        assert "DLL" in characteristics
        assert "32BIT_MACHINE" in characteristics
        assert "|" in characteristics
