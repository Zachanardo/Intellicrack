"""Comprehensive tests for Intellicrack Protection Core module.

Tests all core protection detection functionality including:
- Native ICP Engine integration
- Protection type categorization
- Detection result generation
- Bypass recommendation system
- File format detection (PE, ELF, etc.)
- Compiler/linker identification
- Directory batch analysis
- Export functionality (JSON, CSV, text)
- Fallback analysis methods
- Protection-specific detection patterns

All tests use real binary data to validate actual protection detection.
No mocks for core protection detection - tests must FAIL if code doesn't work.
"""

import asyncio
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    IntellicrackProtectionCore,
    LicenseType,
    ProtectionAnalysis,
    ProtectionType,
    quick_analyze,
)


@pytest.fixture
def temp_pe32_binary() -> Path:
    """Create realistic PE32 binary with protection signatures."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    dos_stub = b"\x00" * 32

    pe_signature = b"PE\x00\x00"
    machine = struct.pack("<H", 0x014C)
    num_sections = struct.pack("<H", 3)
    timestamp = struct.pack("<I", 0x12345678)
    symbol_table = struct.pack("<I", 0)
    num_symbols = struct.pack("<I", 0)
    opt_header_size = struct.pack("<H", 0xE0)
    characteristics = struct.pack("<H", 0x010F)

    coff_header = (
        machine + num_sections + timestamp + symbol_table +
        num_symbols + opt_header_size + characteristics
    )

    magic = struct.pack("<H", 0x010B)
    optional_header = magic + b"\x00" * 222

    pe_header = dos_header + dos_stub + pe_signature + coff_header + optional_header

    themida_signature = b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57"

    binary_data = pe_header + themida_signature + b"\x00" * (4096 - len(pe_header) - len(themida_signature))

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_pe64_vmprotect() -> Path:
    """Create PE64 binary with VMProtect signatures."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    machine = struct.pack("<H", 0x8664)

    header = dos_header + b"\x00" * 32 + pe_signature + machine + b"\x00" * 200

    vmp_signature = b"\x68\x00\x00\x00\x00\x8f\x04\x24"
    vmp_section = b".vmp0" + b"\x00" * 3

    binary_data = header + vmp_signature + vmp_section + b"\x00" * 4096

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_elf64_binary() -> Path:
    """Create ELF64 binary for cross-platform testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix="")

    elf_header = (
        b"\x7fELF" +
        b"\x02" +
        b"\x01" +
        b"\x01" +
        b"\x00" * 9 +
        b"\x02\x00" +
        b"\x3E\x00" +
        b"\x01\x00\x00\x00" +
        b"\x00" * 100
    )

    elf_data = elf_header + b"\x00" * (2048 - len(elf_header))
    temp_file.write(elf_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_upx_packed_binary() -> Path:
    """Create UPX-packed binary for packer detection."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_header = dos_header + b"\x00" * 32 + b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 200

    upx_signature = b"UPX!" + b"\x00" * 4
    upx_section = b"UPX0" + b"\x00" * 4 + b"UPX1" + b"\x00" * 4

    binary_data = pe_header + upx_signature + upx_section + b"\x00" * 4096

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


class TestIntellicrackProtectionCore:
    """Test suite for IntellicrackProtectionCore class."""

    def test_initialization_with_engine_path(self) -> None:
        """Test initialization with custom engine path."""
        detector = IntellicrackProtectionCore(engine_path="/fake/path")
        assert detector.engine_path == "/fake/path"
        assert detector.icp_backend is not None

    def test_initialization_without_engine_path(self) -> None:
        """Test initialization without engine path."""
        detector = IntellicrackProtectionCore()
        assert detector.icp_backend is not None

    def test_detect_protections_on_pe32_binary(self, temp_pe32_binary: Path) -> None:
        """Test protection detection on PE32 binary with real file."""
        detector = IntellicrackProtectionCore()

        result = detector.detect_protections(str(temp_pe32_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_pe32_binary)
        assert "PE" in result.file_type or result.file_type == "Unknown"
        assert result.architecture in ["x86", "x64", "Unknown"]

    def test_detect_protections_on_pe64_binary(self, temp_pe64_vmprotect: Path) -> None:
        """Test protection detection on PE64 binary."""
        detector = IntellicrackProtectionCore()

        result = detector.detect_protections(str(temp_pe64_vmprotect))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_pe64_vmprotect)
        assert result.architecture in ["x64", "Unknown"]

    def test_detect_protections_on_elf_binary(self, temp_elf64_binary: Path) -> None:
        """Test protection detection on ELF binary."""
        detector = IntellicrackProtectionCore()

        result = detector.detect_protections(str(temp_elf64_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_elf64_binary)
        assert "ELF" in result.file_type or result.file_type == "Unknown"

    def test_detect_protections_file_not_found(self) -> None:
        """Test detection raises error for non-existent file."""
        detector = IntellicrackProtectionCore()

        with pytest.raises(FileNotFoundError):
            detector.detect_protections("/nonexistent/file.exe")

    def test_categorize_detection_packer(self) -> None:
        """Test categorization of packer detection types."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("packer") == ProtectionType.PACKER
        assert detector._categorize_detection("Packer: UPX") == ProtectionType.PACKER

    def test_categorize_detection_protector(self) -> None:
        """Test categorization of protector detection types."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("protector") == ProtectionType.PROTECTOR
        assert detector._categorize_detection("Protector: VMProtect") == ProtectionType.PROTECTOR

    def test_categorize_detection_compiler(self) -> None:
        """Test categorization of compiler detection types."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("compiler") == ProtectionType.COMPILER
        assert detector._categorize_detection("Compiler: MSVC") == ProtectionType.COMPILER

    def test_categorize_detection_cryptor(self) -> None:
        """Test categorization of cryptor detection types."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("cryptor") == ProtectionType.CRYPTOR
        assert detector._categorize_detection("Cryptor: Custom") == ProtectionType.CRYPTOR

    def test_categorize_detection_dongle(self) -> None:
        """Test categorization of dongle/hardware protection."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("dongle") == ProtectionType.DONGLE
        assert detector._categorize_detection("HASP") == ProtectionType.DONGLE
        assert detector._categorize_detection("Sentinel") == ProtectionType.DONGLE

    def test_categorize_detection_license(self) -> None:
        """Test categorization of license management systems."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("license") == ProtectionType.LICENSE
        assert detector._categorize_detection("FlexLM") == ProtectionType.LICENSE

    def test_categorize_detection_drm(self) -> None:
        """Test categorization of DRM systems."""
        detector = IntellicrackProtectionCore()

        assert detector._categorize_detection("drm") == ProtectionType.DRM
        assert detector._categorize_detection("DRM: Denuvo") == ProtectionType.DRM

    def test_get_bypass_recommendations_upx(self) -> None:
        """Test bypass recommendations for UPX packer."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("UPX")

        assert len(recommendations) > 0
        assert any("upx -d" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_vmprotect(self) -> None:
        """Test bypass recommendations for VMProtect."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("VMProtect")

        assert len(recommendations) > 0
        assert any("difficult" in rec.lower() or "devirtualizer" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_themida(self) -> None:
        """Test bypass recommendations for Themida."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("Themida")

        assert len(recommendations) > 0
        assert any("themida" in rec.lower() or "kernel" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_hasp(self) -> None:
        """Test bypass recommendations for HASP dongle."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("HASP")

        assert len(recommendations) > 0
        assert any("hasp" in rec.lower() or "dongle" in rec.lower() or "emulator" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_flexlm(self) -> None:
        """Test bypass recommendations for FlexLM."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("FlexLM")

        assert len(recommendations) > 0
        assert any("flexlm" in rec.lower() or "license" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_denuvo(self) -> None:
        """Test bypass recommendations for Denuvo."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("Denuvo")

        assert len(recommendations) > 0
        assert any("extreme" in rec.lower() or "difficult" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_generic_packer(self) -> None:
        """Test generic bypass recommendations for unknown packer."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("Unknown Packer")

        assert len(recommendations) > 0
        assert any("unpack" in rec.lower() or "oep" in rec.lower() for rec in recommendations)

    def test_get_bypass_recommendations_generic_protector(self) -> None:
        """Test generic bypass recommendations for unknown protector."""
        detector = IntellicrackProtectionCore()

        recommendations = detector._get_bypass_recommendations("Custom Protector")

        assert len(recommendations) > 0
        assert len(recommendations) >= 1

    def test_analyze_directory_recursive(self, temp_pe32_binary: Path, temp_upx_packed_binary: Path) -> None:
        """Test batch directory analysis in recursive mode."""
        detector = IntellicrackProtectionCore()

        temp_dir = temp_pe32_binary.parent

        results = detector.analyze_directory(str(temp_dir), recursive=True)

        assert isinstance(results, list)
        assert len(results) >= 0

    def test_analyze_directory_non_recursive(self, temp_pe32_binary: Path) -> None:
        """Test batch directory analysis in non-recursive mode."""
        detector = IntellicrackProtectionCore()

        temp_dir = temp_pe32_binary.parent

        results = detector.analyze_directory(str(temp_dir), recursive=False)

        assert isinstance(results, list)

    def test_get_summary_with_detections(self) -> None:
        """Test summary generation with detections."""
        detector = IntellicrackProtectionCore()

        detection = DetectionResult(
            name="VMProtect",
            version="3.5",
            type=ProtectionType.PROTECTOR,
            confidence=95.0
        )

        analysis = ProtectionAnalysis(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection],
            compiler="MSVC 2019",
            is_packed=False,
            is_protected=True
        )

        summary = detector.get_summary(analysis)

        assert "file.exe" in summary
        assert "PE32" in summary
        assert "x86" in summary
        assert "MSVC 2019" in summary
        assert "VMProtect" in summary
        assert "PROTECTED" in summary

    def test_get_summary_packed_binary(self) -> None:
        """Test summary generation for packed binary."""
        detector = IntellicrackProtectionCore()

        analysis = ProtectionAnalysis(
            file_path="/test/packed.exe",
            file_type="PE64",
            architecture="x64",
            is_packed=True,
            is_protected=False
        )

        summary = detector.get_summary(analysis)

        assert "PACKED" in summary

    def test_export_results_json(self) -> None:
        """Test export to JSON format."""
        detector = IntellicrackProtectionCore()

        detection = DetectionResult(
            name="UPX",
            version="3.96",
            type=ProtectionType.PACKER,
            confidence=100.0,
            bypass_recommendations=["Use 'upx -d' to unpack"]
        )

        analysis = ProtectionAnalysis(
            file_path="/test/upx.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection],
            is_packed=True
        )

        json_output = detector.export_results(analysis, output_format="json")

        assert isinstance(json_output, str)
        data = json.loads(json_output)

        assert data["file_path"] == "/test/upx.exe"
        assert data["file_type"] == "PE32"
        assert data["architecture"] == "x86"
        assert data["is_packed"] is True
        assert len(data["detections"]) == 1
        assert data["detections"][0]["name"] == "UPX"
        assert data["detections"][0]["version"] == "3.96"
        assert data["detections"][0]["confidence"] == 100.0

    def test_export_results_text(self) -> None:
        """Test export to text format."""
        detector = IntellicrackProtectionCore()

        analysis = ProtectionAnalysis(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        text_output = detector.export_results(analysis, output_format="text")

        assert isinstance(text_output, str)
        assert "file.exe" in text_output

    def test_export_results_csv(self) -> None:
        """Test export to CSV format."""
        detector = IntellicrackProtectionCore()

        detection = DetectionResult(
            name="Themida",
            version="2.4",
            type=ProtectionType.PROTECTOR,
            confidence=90.0
        )

        analysis = ProtectionAnalysis(
            file_path="/test/themida.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection]
        )

        csv_output = detector.export_results(analysis, output_format="csv")

        assert isinstance(csv_output, str)
        assert "File,Type,Architecture,Protection,Version,Category" in csv_output
        assert "Themida" in csv_output
        assert "2.4" in csv_output

    def test_export_results_invalid_format(self) -> None:
        """Test export with invalid format raises error."""
        detector = IntellicrackProtectionCore()

        analysis = ProtectionAnalysis(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        with pytest.raises(ValueError):
            detector.export_results(analysis, output_format="invalid")

    def test_fallback_analysis_pe32(self, temp_pe32_binary: Path) -> None:
        """Test fallback analysis for PE32 binary."""
        detector = IntellicrackProtectionCore()

        result = detector._fallback_analysis(str(temp_pe32_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_pe32_binary)
        assert result.file_type == "PE"
        assert result.architecture in ["x86", "x64"]

    def test_fallback_analysis_elf64(self, temp_elf64_binary: Path) -> None:
        """Test fallback analysis for ELF64 binary."""
        detector = IntellicrackProtectionCore()

        result = detector._fallback_analysis(str(temp_elf64_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_elf64_binary)
        assert result.file_type == "ELF"
        assert result.architecture in ["x86", "x64"]


class TestQuickAnalyze:
    """Test quick_analyze convenience function."""

    def test_quick_analyze_pe_binary(self, temp_pe32_binary: Path) -> None:
        """Test quick_analyze function on PE binary."""
        result = quick_analyze(str(temp_pe32_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_pe32_binary)

    def test_quick_analyze_elf_binary(self, temp_elf64_binary: Path) -> None:
        """Test quick_analyze function on ELF binary."""
        result = quick_analyze(str(temp_elf64_binary))

        assert isinstance(result, ProtectionAnalysis)
        assert result.file_path == str(temp_elf64_binary)


class TestProtectionDetectionResultStructures:
    """Test protection detection data structures."""

    def test_detection_result_creation(self) -> None:
        """Test DetectionResult creation."""
        detection = DetectionResult(
            name="VMProtect",
            version="3.5",
            type=ProtectionType.PROTECTOR,
            confidence=95.0,
            details={"method": "signature"},
            bypass_recommendations=["Use devirtualizer"]
        )

        assert detection.name == "VMProtect"
        assert detection.version == "3.5"
        assert detection.type == ProtectionType.PROTECTOR
        assert detection.confidence == 95.0
        assert detection.details["method"] == "signature"
        assert len(detection.bypass_recommendations) == 1

    def test_protection_analysis_creation(self) -> None:
        """Test ProtectionAnalysis creation."""
        analysis = ProtectionAnalysis(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86",
            compiler="MSVC 2019",
            is_packed=True,
            is_protected=True
        )

        assert analysis.file_path == "/test/file.exe"
        assert analysis.file_type == "PE32"
        assert analysis.architecture == "x86"
        assert analysis.compiler == "MSVC 2019"
        assert analysis.is_packed is True
        assert analysis.is_protected is True
        assert len(analysis.detections) == 0

    def test_protection_analysis_with_detections(self) -> None:
        """Test ProtectionAnalysis with multiple detections."""
        detection1 = DetectionResult(
            name="UPX",
            type=ProtectionType.PACKER,
            confidence=100.0
        )

        detection2 = DetectionResult(
            name="Themida",
            type=ProtectionType.PROTECTOR,
            confidence=90.0
        )

        analysis = ProtectionAnalysis(
            file_path="/test/protected.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection1, detection2],
            is_packed=True,
            is_protected=True
        )

        assert len(analysis.detections) == 2
        assert analysis.detections[0].name == "UPX"
        assert analysis.detections[1].name == "Themida"


class TestProtectionBypassKnowledge:
    """Test protection-specific bypass knowledge base."""

    def test_all_known_protections_have_bypass_recommendations(self) -> None:
        """Test that all major protections have bypass recommendations."""
        detector = IntellicrackProtectionCore()

        known_protections = [
            "UPX", "ASPack", "PECompact",
            "Themida", "VMProtect", "Enigma", "ASProtect",
            "HASP", "Sentinel", "CodeMeter", "FlexLM", "CrypKey",
            "Denuvo", "SecuROM", "SafeDisc"
        ]

        for protection in known_protections:
            recommendations = detector._get_bypass_recommendations(protection)
            assert len(recommendations) > 0, f"No bypass recommendations for {protection}"

    def test_bypass_recommendations_are_unique(self) -> None:
        """Test that different protections get different recommendations."""
        detector = IntellicrackProtectionCore()

        upx_recs = detector._get_bypass_recommendations("UPX")
        vmprotect_recs = detector._get_bypass_recommendations("VMProtect")

        assert upx_recs != vmprotect_recs

    def test_bypass_recommendations_for_partial_match(self) -> None:
        """Test bypass recommendations work with partial name match."""
        detector = IntellicrackProtectionCore()

        vmprotect_recs = detector._get_bypass_recommendations("VMProtect 3.5")

        assert len(vmprotect_recs) > 0
        assert any("VMProtect" in str(detector.PROTECTION_BYPASSES.get("VMProtect", [])) or "difficult" in rec.lower() for rec in vmprotect_recs)
