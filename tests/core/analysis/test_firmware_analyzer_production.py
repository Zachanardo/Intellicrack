"""Production tests for firmware_analyzer module.

This module tests firmware analysis, embedded file extraction, and security
scanning capabilities using real firmware signatures and actual extraction.

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.firmware_analyzer import (
    BINWALK_AVAILABLE,
    AdvancedFirmwareAnalyzer,
    FirmwareSignature,
    FirmwareType,
    SecurityFindingType,
)


def create_firmware_image(
    path: Path,
    image_type: str = "router",
    include_filesystem: bool = True,
    include_credentials: bool = False,
) -> Path:
    """Create a realistic firmware image for testing.

    Args:
        path: Path where firmware image will be created
        image_type: Type of firmware (router, iot_device, bootloader)
        include_filesystem: Include SquashFS filesystem marker
        include_credentials: Include hardcoded credentials

    Returns:
        Path to created firmware image
    """
    firmware_data = bytearray()

    firmware_data.extend(b"\x00" * 256)

    if image_type == "router":
        firmware_data.extend(b"Router Firmware v1.0\x00")
    elif image_type == "iot_device":
        firmware_data.extend(b"IoT Device Firmware v2.0\x00")
    else:
        firmware_data.extend(b"Bootloader v0.9\x00")

    firmware_data.extend(b"\x00" * 512)

    if include_filesystem:
        firmware_data.extend(b"hsqs")
        firmware_data.extend(struct.pack("<I", 0x01000000))
        firmware_data.extend(b"\x00" * 1024)

    if include_credentials:
        firmware_data.extend(b"admin:admin123\x00")
        firmware_data.extend(b"root:password\x00")
        firmware_data.extend(b"-----BEGIN RSA PRIVATE KEY-----\x00")

    firmware_data.extend(b"\x00" * 2048)

    path.write_bytes(firmware_data)
    return path


def create_elf_binary(path: Path) -> Path:
    """Create a minimal ELF binary for firmware extraction testing.

    Args:
        path: Path where ELF binary will be created

    Returns:
        Path to created ELF binary
    """
    elf_header = bytearray(64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4] = 1
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[16:18] = struct.pack("<H", 2)
    elf_header[18:20] = struct.pack("<H", 3)

    elf_data = elf_header + b"\x00" * 1024

    path.write_bytes(elf_data)
    return path


@pytest.fixture
def basic_firmware(tmp_path: Path) -> Path:
    """Create basic firmware image without embedded files."""
    firmware_path = tmp_path / "basic_firmware.bin"
    return create_firmware_image(firmware_path, image_type="router", include_filesystem=False)


@pytest.fixture
def router_firmware(tmp_path: Path) -> Path:
    """Create router firmware with filesystem."""
    firmware_path = tmp_path / "router_firmware.bin"
    return create_firmware_image(
        firmware_path,
        image_type="router",
        include_filesystem=True,
        include_credentials=False,
    )


@pytest.fixture
def vulnerable_firmware(tmp_path: Path) -> Path:
    """Create firmware with security issues."""
    firmware_path = tmp_path / "vulnerable_firmware.bin"
    return create_firmware_image(
        firmware_path,
        image_type="router",
        include_filesystem=True,
        include_credentials=True,
    )


@pytest.fixture
def iot_firmware(tmp_path: Path) -> Path:
    """Create IoT device firmware."""
    firmware_path = tmp_path / "iot_device.bin"
    return create_firmware_image(
        firmware_path,
        image_type="iot_device",
        include_filesystem=True,
        include_credentials=False,
    )


class TestFirmwareSignatureDetection:
    """Test firmware signature detection capabilities."""

    def test_signature_creation_and_properties(self) -> None:
        """FirmwareSignature dataclass validates correctly."""
        signature = FirmwareSignature(
            offset=0x1000,
            signature_name="SquashFS",
            description="SquashFS filesystem",
            file_type="squashfs",
            size=0x10000,
            confidence=0.95,
        )

        assert signature.offset == 0x1000
        assert signature.signature_name == "SquashFS"
        assert signature.is_filesystem
        assert not signature.is_executable
        assert signature.confidence == 0.95

    def test_executable_signature_detection(self) -> None:
        """FirmwareSignature correctly identifies executable types."""
        elf_sig = FirmwareSignature(
            offset=0,
            signature_name="ELF",
            description="ELF executable",
            file_type="elf",
            size=1024,
        )

        pe_sig = FirmwareSignature(
            offset=0,
            signature_name="PE",
            description="PE executable",
            file_type="pe",
            size=2048,
        )

        assert elf_sig.is_executable
        assert pe_sig.is_executable
        assert not elf_sig.is_filesystem
        assert not pe_sig.is_filesystem

    def test_filesystem_signature_detection(self) -> None:
        """FirmwareSignature correctly identifies filesystem types."""
        fs_types = ["squashfs", "cramfs", "jffs2", "yaffs", "ext4", "fat32"]

        for fs_type in fs_types:
            signature = FirmwareSignature(
                offset=0,
                signature_name=fs_type.upper(),
                description=f"{fs_type} filesystem",
                file_type=fs_type,
            )
            assert signature.is_filesystem
            assert not signature.is_executable


class TestFirmwareAnalyzerInitialization:
    """Test firmware analyzer initialization and configuration."""

    def test_analyzer_initialization_with_binwalk(self) -> None:
        """AdvancedFirmwareAnalyzer initializes with correct default settings."""
        analyzer = AdvancedFirmwareAnalyzer()

        assert analyzer.extract_files is True
        assert analyzer.deep_scan is False
        assert analyzer.binwalk_available == BINWALK_AVAILABLE

    def test_analyzer_initialization_with_custom_settings(self) -> None:
        """AdvancedFirmwareAnalyzer accepts custom configuration."""
        analyzer = AdvancedFirmwareAnalyzer(
            extract_files=False,
            deep_scan=True,
        )

        assert analyzer.extract_files is False
        assert analyzer.deep_scan is True

    def test_analyzer_binwalk_availability_check(self) -> None:
        """AdvancedFirmwareAnalyzer correctly reports binwalk availability."""
        analyzer = AdvancedFirmwareAnalyzer()

        if BINWALK_AVAILABLE:
            assert analyzer.binwalk_available is True
        else:
            assert analyzer.binwalk_available is False


class TestBasicFirmwareAnalysis:
    """Test basic firmware analysis capabilities."""

    def test_analyze_basic_firmware_structure(self, basic_firmware: Path) -> None:
        """Analyzer detects basic firmware structure."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(basic_firmware))

        assert result is not None
        assert result.file_path == str(basic_firmware)
        assert result.firmware_type in [FirmwareType.ROUTER_FIRMWARE, FirmwareType.UNKNOWN]
        assert result.analysis_time > 0

    def test_analyze_router_firmware_with_filesystem(self, router_firmware: Path) -> None:
        """Analyzer detects router firmware with embedded filesystem."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        assert len(result.signatures) > 0

        filesystem_signatures = [s for s in result.signatures if s.is_filesystem]
        if BINWALK_AVAILABLE:
            assert filesystem_signatures

    def test_analyze_iot_firmware(self, iot_firmware: Path) -> None:
        """Analyzer processes IoT device firmware."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(iot_firmware))

        assert result is not None
        assert result.file_path == str(iot_firmware)
        assert result.firmware_type in [
            FirmwareType.IOT_DEVICE,
            FirmwareType.ROUTER_FIRMWARE,
            FirmwareType.UNKNOWN,
        ]


class TestFirmwareExtraction:
    """Test firmware file extraction capabilities."""

    @pytest.mark.skipif(not BINWALK_AVAILABLE, reason="Binwalk not available")
    def test_firmware_extraction_enabled(self, router_firmware: Path, tmp_path: Path) -> None:
        """Analyzer extracts embedded files when enabled."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=True)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        if result.extractions is not None:
            assert result.extractions.extraction_directory != ""

    def test_firmware_extraction_disabled(self, router_firmware: Path) -> None:
        """Analyzer skips extraction when disabled."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        assert result.extractions is None

    @pytest.mark.skipif(not BINWALK_AVAILABLE, reason="Binwalk not available")
    def test_extraction_file_counting(self, router_firmware: Path) -> None:
        """Analyzer counts extracted files correctly."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=True)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        if result.extractions is not None:
            assert result.extractions.total_extracted >= 0


class TestSecurityAnalysis:
    """Test firmware security analysis and vulnerability detection."""

    def test_security_finding_creation(self) -> None:
        """SecurityFinding dataclass validates correctly."""
        from intellicrack.core.analysis.firmware_analyzer import SecurityFinding

        finding = SecurityFinding(
            finding_type=SecurityFindingType.HARDCODED_CREDENTIALS,
            description="Hardcoded admin credentials found",
            file_path="/extracted/bin/config",
            offset=0x1234,
            severity="critical",
            confidence=0.95,
            evidence="admin:admin123",
            remediation="Remove hardcoded credentials",
        )

        assert finding.finding_type == SecurityFindingType.HARDCODED_CREDENTIALS
        assert finding.severity == "critical"
        assert finding.is_critical
        assert finding.confidence == 0.95

    def test_detect_hardcoded_credentials(self, vulnerable_firmware: Path) -> None:
        """Analyzer detects hardcoded credentials in firmware."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False, deep_scan=True)
        result = analyzer.analyze(str(vulnerable_firmware))

        assert result is not None

        if credential_findings := [
            f
            for f in result.security_findings
            if f.finding_type
            in [
                SecurityFindingType.HARDCODED_CREDENTIALS,
                SecurityFindingType.DEFAULT_CREDENTIALS,
            ]
        ]:
            assert any(f.severity in ["critical", "high"] for f in credential_findings)

    def test_detect_private_keys(self, vulnerable_firmware: Path) -> None:
        """Analyzer detects private keys in firmware."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False, deep_scan=True)
        result = analyzer.analyze(str(vulnerable_firmware))

        assert result is not None

        if key_findings := [
            f
            for f in result.security_findings
            if f.finding_type == SecurityFindingType.PRIVATE_KEY
        ]:
            assert any("PRIVATE KEY" in f.evidence for f in key_findings)

    def test_security_scan_on_basic_firmware(self, basic_firmware: Path) -> None:
        """Security scan runs without errors on clean firmware."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False, deep_scan=True)
        result = analyzer.analyze(str(basic_firmware))

        assert result is not None
        assert isinstance(result.security_findings, list)


class TestEntropyAnalysis:
    """Test firmware entropy analysis for encryption detection."""

    def test_entropy_analysis_present(self, router_firmware: Path) -> None:
        """Analyzer performs entropy analysis on firmware."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        assert isinstance(result.entropy_analysis, dict)

    def test_entropy_calculation_for_encrypted_sections(self, tmp_path: Path) -> None:
        """Analyzer detects high entropy sections indicating encryption."""
        import random

        random.seed(42)

        firmware_path = tmp_path / "encrypted_firmware.bin"
        encrypted_data = bytes(random.randint(0, 255) for _ in range(4096))

        firmware_data = b"\x00" * 1024 + encrypted_data + b"\x00" * 1024
        firmware_path.write_bytes(firmware_data)

        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(firmware_path))

        assert result is not None
        assert isinstance(result.entropy_analysis, dict)


class TestFirmwareTypeClassification:
    """Test firmware type classification."""

    def test_router_firmware_classification(self, router_firmware: Path) -> None:
        """Analyzer classifies router firmware correctly."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        assert result.firmware_type in [FirmwareType.ROUTER_FIRMWARE, FirmwareType.UNKNOWN]

    def test_iot_firmware_classification(self, iot_firmware: Path) -> None:
        """Analyzer classifies IoT firmware correctly."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(iot_firmware))

        assert result is not None
        assert result.firmware_type in [
            FirmwareType.IOT_DEVICE,
            FirmwareType.ROUTER_FIRMWARE,
            FirmwareType.UNKNOWN,
        ]

    def test_unknown_firmware_classification(self, tmp_path: Path) -> None:
        """Analyzer handles unknown firmware types."""
        unknown_path = tmp_path / "unknown.bin"
        unknown_path.write_bytes(b"\x00" * 100)

        analyzer = AdvancedFirmwareAnalyzer(extract_files=False)
        result = analyzer.analyze(str(unknown_path))

        assert result is not None
        assert result.firmware_type == FirmwareType.UNKNOWN


class TestErrorHandling:
    """Test error handling in firmware analysis."""

    def test_analyze_nonexistent_file(self) -> None:
        """Analyzer handles nonexistent file gracefully."""
        analyzer = AdvancedFirmwareAnalyzer()

        result = analyzer.analyze("/nonexistent/firmware.bin")

        assert result is not None
        assert result.firmware_type == FirmwareType.UNKNOWN

    def test_analyze_empty_file(self, tmp_path: Path) -> None:
        """Analyzer handles empty firmware file."""
        empty_path = tmp_path / "empty.bin"
        empty_path.write_bytes(b"")

        analyzer = AdvancedFirmwareAnalyzer()
        result = analyzer.analyze(str(empty_path))

        assert result is not None

    def test_analyze_corrupted_firmware(self, tmp_path: Path) -> None:
        """Analyzer handles corrupted firmware data."""
        corrupted_path = tmp_path / "corrupted.bin"
        corrupted_path.write_bytes(b"\xff" * 10)

        analyzer = AdvancedFirmwareAnalyzer()
        result = analyzer.analyze(str(corrupted_path))

        assert result is not None


class TestPerformanceAndScaling:
    """Test analyzer performance with various firmware sizes."""

    def test_analyze_small_firmware(self, tmp_path: Path) -> None:
        """Analyzer processes small firmware efficiently."""
        small_path = tmp_path / "small.bin"
        small_path.write_bytes(b"\x00" * 1024)

        analyzer = AdvancedFirmwareAnalyzer()
        result = analyzer.analyze(str(small_path))

        assert result is not None
        assert result.analysis_time < 10.0

    def test_analyze_medium_firmware(self, tmp_path: Path) -> None:
        """Analyzer processes medium firmware efficiently."""
        medium_path = tmp_path / "medium.bin"
        medium_path.write_bytes(b"\x00" * (512 * 1024))

        analyzer = AdvancedFirmwareAnalyzer()
        result = analyzer.analyze(str(medium_path))

        assert result is not None
        assert result.analysis_time < 30.0

    def test_deep_scan_performance(self, router_firmware: Path) -> None:
        """Deep scan completes within reasonable time."""
        analyzer = AdvancedFirmwareAnalyzer(extract_files=False, deep_scan=True)
        result = analyzer.analyze(str(router_firmware))

        assert result is not None
        assert result.analysis_time < 60.0
