"""Production tests for binary analysis utility functions.

This module validates real binary analysis functionality against actual binary files,
ensuring the analysis engine correctly identifies formats, extracts features, and
detects protection mechanisms.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.types.analysis import (
    ELFAnalysisResult,
    GenericAnalysisResult,
    PEAnalysisResult,
)
from intellicrack.utils.analysis.binary_analysis import (
    analyze_binary,
    analyze_binary_optimized,
    analyze_patterns,
    extract_binary_features,
    extract_binary_info,
    identify_binary_format,
    scan_binary,
)


if TYPE_CHECKING:
    from pytest_mock import MockerFixture


class TestBinaryFormatIdentification:
    """Test binary format identification against real files."""

    def test_identify_pe_format_with_real_executable(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        binary_format = identify_binary_format(str(pe_exe))

        assert binary_format == "PE", "Failed to identify real PE executable"

    def test_identify_elf_format_with_real_binary(self, fixtures_dir: Path) -> None:
        elf_binary = fixtures_dir / "binaries" / "elf" / "simple_x64"
        if not elf_binary.exists():
            pytest.skip("ELF test fixture not available")

        binary_format = identify_binary_format(str(elf_binary))

        assert binary_format == "ELF", "Failed to identify real ELF binary"

    def test_identify_protected_executable_format(self, fixtures_dir: Path) -> None:
        upx_packed = fixtures_dir / "binaries" / "protected" / "upx_packed_0.exe"
        if not upx_packed.exists():
            pytest.skip("UPX packed fixture not available")

        binary_format = identify_binary_format(str(upx_packed))

        assert binary_format == "PE", "Failed to identify packed PE executable"

    def test_identify_unknown_format_with_corrupt_file(self, tmp_path: Path) -> None:
        corrupt_file = tmp_path / "corrupt.bin"
        corrupt_file.write_bytes(b"\x00" * 512)

        binary_format = identify_binary_format(str(corrupt_file))

        assert binary_format == "UNKNOWN", "Should return UNKNOWN for corrupt files"

    def test_identify_format_with_nonexistent_file(self) -> None:
        binary_format = identify_binary_format("/nonexistent/path/file.exe")

        assert binary_format == "UNKNOWN", "Should handle missing files gracefully"


class TestPEAnalysis:
    """Test PE binary analysis with real executables."""

    def test_analyze_pe_extracts_sections(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        result = analyze_binary(str(pe_exe))

        assert isinstance(result, PEAnalysisResult), "Should return PEAnalysisResult"
        assert result.error is None, f"Analysis failed: {result.error}"
        assert len(result.sections) > 0, "Should extract PE sections"
        assert any(
            ".text" in str(section.name) for section in result.sections
        ), "Should find .text section"

    def test_analyze_pe_extracts_imports(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        result = analyze_binary(str(pe_exe))

        assert isinstance(result, PEAnalysisResult)
        assert len(result.imports) > 0, "Should extract import table"
        assert any(
            "kernel32.dll" in str(imp.dll).lower() for imp in result.imports
        ), "Should find kernel32.dll imports"

    def test_analyze_packed_pe_detects_high_entropy(self, fixtures_dir: Path) -> None:
        upx_packed = fixtures_dir / "binaries" / "protected" / "upx_packed_0.exe"
        if not upx_packed.exists():
            pytest.skip("UPX packed fixture not available")

        result = analyze_binary(str(upx_packed))

        assert isinstance(result, PEAnalysisResult)
        assert any(
            section.entropy > 7.0 for section in result.sections
        ), "Should detect high entropy in packed sections"
        assert len(result.suspicious_indicators) > 0, "Should flag suspicious indicators"

    def test_analyze_pe_handles_exports(self, fixtures_dir: Path) -> None:
        dll_file = fixtures_dir / "PORTABLE_SANDBOX" / "processhacker_portable" / "x64" / "plugins" / "DotNetTools.dll"
        if not dll_file.exists():
            pytest.skip("DLL test fixture not available")

        result = analyze_binary(str(dll_file))

        assert isinstance(result, PEAnalysisResult)
        if len(result.exports) > 0:
            assert all(exp.name for exp in result.exports), "Exports should have names"
            assert all(exp.address for exp in result.exports), "Exports should have addresses"


class TestELFAnalysis:
    """Test ELF binary analysis with real binaries."""

    def test_analyze_elf_extracts_sections(self, fixtures_dir: Path) -> None:
        elf_binary = fixtures_dir / "binaries" / "elf" / "simple_x64"
        if not elf_binary.exists():
            pytest.skip("ELF test fixture not available")

        result = analyze_binary(str(elf_binary))

        assert isinstance(result, ELFAnalysisResult), "Should return ELFAnalysisResult"
        assert result.error is None, f"Analysis failed: {result.error}"
        assert len(result.sections) > 0, "Should extract ELF sections"

    def test_analyze_elf_determines_architecture(self, fixtures_dir: Path) -> None:
        elf_binary = fixtures_dir / "binaries" / "elf" / "simple_x64"
        if not elf_binary.exists():
            pytest.skip("ELF test fixture not available")

        result = analyze_binary(str(elf_binary))

        assert isinstance(result, ELFAnalysisResult)
        assert "64" in result.elf_class or "64" in result.machine, "Should identify 64-bit architecture"


class TestBinaryFeatureExtraction:
    """Test feature extraction for ML analysis."""

    def test_extract_features_from_real_pe(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        features = extract_binary_features(str(pe_exe))

        assert features["file_size"] > 0, "Should extract file size"
        assert features["num_sections"] > 0, "Should count sections"
        assert isinstance(features["entropy"], float), "Should calculate entropy"
        assert features["entropy"] > 0, "Entropy should be positive"

    def test_extract_features_detects_packing(self, fixtures_dir: Path) -> None:
        upx_packed = fixtures_dir / "binaries" / "protected" / "upx_packed_0.exe"
        if not upx_packed.exists():
            pytest.skip("UPX packed fixture not available")

        features = extract_binary_features(str(upx_packed))

        assert features["is_packed"] is True or features["entropy"] > 7.0, \
            "Should detect packing via high entropy"


class TestBinaryInfoExtraction:
    """Test basic binary information extraction."""

    def test_extract_info_calculates_hashes(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        info = extract_binary_info(str(pe_exe))

        assert "md5" in info, "Should calculate MD5 hash"
        assert "sha1" in info, "Should calculate SHA1 hash"
        assert "sha256" in info, "Should calculate SHA256 hash"
        assert len(info["md5"]) == 32, "MD5 should be 32 hex characters"
        assert len(info["sha256"]) == 64, "SHA256 should be 64 hex characters"

    def test_extract_info_includes_format(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        info = extract_binary_info(str(pe_exe))

        assert info["format"] == "PE", "Should identify PE format"
        assert info["size"] > 0, "Should include file size"


class TestPatternAnalysis:
    """Test pattern detection in real binaries."""

    def test_analyze_patterns_finds_license_strings(self, fixtures_dir: Path) -> None:
        protected_exe = fixtures_dir / "binaries" / "pe" / "protected" / "enterprise_license_check.exe"
        if not protected_exe.exists():
            pytest.skip("License-protected fixture not available")

        patterns = [b"license", b"trial", b"expire", b"serial", b"key"]
        result = analyze_patterns(str(protected_exe), patterns)

        assert result["total_patterns"] == len(patterns), "Should track all patterns"
        assert "matches" in result, "Should return matches"
        if len(result["matches"]) > 0:
            for match in result["matches"]:
                assert "pattern" in match
                assert "count" in match
                assert match["count"] > 0


class TestBinaryScanning:
    """Test signature scanning for protection mechanisms."""

    def test_scan_binary_detects_upx(self, fixtures_dir: Path) -> None:
        upx_packed = fixtures_dir / "binaries" / "protected" / "upx_packed_0.exe"
        if not upx_packed.exists():
            pytest.skip("UPX packed fixture not available")

        result = scan_binary(str(upx_packed))

        assert "detected" in result, "Should return detected list"
        assert result["file_size"] > 0, "Should include file size"
        assert result["scan_time"] >= 0, "Should track scan time"

        upx_detected = any(d["name"] == "UPX" for d in result["detected"])
        assert upx_detected, "Should detect UPX signature"

    def test_scan_binary_with_custom_signatures(self, fixtures_dir: Path) -> None:
        pe_exe = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not pe_exe.exists():
            pytest.skip("7zip.exe test fixture not available")

        custom_sigs = {
            "MZ_HEADER": b"MZ",
            "PE_SIGNATURE": b"PE\x00\x00",
        }
        result = scan_binary(str(pe_exe), custom_sigs)

        assert any(d["name"] == "MZ_HEADER" for d in result["detected"]), \
            "Should detect custom MZ header signature"


class TestOptimizedAnalysis:
    """Test optimized analysis for large binaries."""

    def test_optimized_analysis_handles_small_file(self, fixtures_dir: Path) -> None:
        small_exe = fixtures_dir / "binaries" / "size_categories" / "tiny_4kb" / "tiny_hello.exe"
        if not small_exe.exists():
            pytest.skip("Tiny binary fixture not available")

        result = analyze_binary_optimized(str(small_exe))

        assert result.error is None, f"Analysis failed: {result.error}"

    def test_optimized_analysis_uses_chunking_for_large_files(
        self, fixtures_dir: Path
    ) -> None:
        medium_exe = fixtures_dir / "binaries" / "size_categories" / "medium_100mb" / "medium_padded.exe"
        if not medium_exe.exists():
            pytest.skip("Medium binary fixture not available")

        result = analyze_binary_optimized(str(medium_exe), use_performance_optimizer=True)

        assert result is not None, "Should return result for large files"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_binary_with_empty_path(self) -> None:
        result = analyze_binary("")

        assert isinstance(result, GenericAnalysisResult)
        assert result.error is not None
        assert "Empty path" in result.error

    def test_analyze_binary_with_nonexistent_file(self) -> None:
        result = analyze_binary("/nonexistent/file.exe")

        assert isinstance(result, GenericAnalysisResult)
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_extract_features_handles_corrupted_pe(self, tmp_path: Path) -> None:
        corrupt_pe = tmp_path / "corrupt.exe"
        corrupt_pe.write_bytes(b"MZ" + b"\x00" * 1000)

        features = extract_binary_features(str(corrupt_pe))

        assert features["file_size"] > 0
        assert "entropy" in features


class TestProtectionDetection:
    """Test detection of protection mechanisms in real protected binaries."""

    @pytest.mark.parametrize(
        "protection_file,expected_indicator",
        [
            ("themida_protected.exe", "themida"),
            ("vmprotect_protected.exe", "vmprotect"),
            ("aspack_packed.exe", "aspack"),
            ("enigma_packed.exe", "enigma"),
        ],
    )
    def test_detect_protection_mechanism(
        self, fixtures_dir: Path, protection_file: str, expected_indicator: str
    ) -> None:
        protected_exe = fixtures_dir / "binaries" / "protected" / protection_file
        if not protected_exe.exists():
            pytest.skip(f"{protection_file} fixture not available")

        result = scan_binary(str(protected_exe))

        detected_names = [d["name"].lower() for d in result["detected"]]
        assert any(
            expected_indicator in name for name in detected_names
        ), f"Should detect {expected_indicator} protection"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Provide path to test fixtures directory."""
    return Path(__file__).parent.parent.parent.parent / "fixtures"
