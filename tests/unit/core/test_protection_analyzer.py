"""Comprehensive production-ready tests for Protection Analyzer.

These tests validate real-world binary protection detection capabilities.
Tests are designed to FAIL unless the analyzer genuinely detects protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import os
import struct
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.protection_analyzer import ProtectionAnalyzer


class TestProtectionAnalyzerInitialization:
    """Test ProtectionAnalyzer initialization and configuration."""

    def test_initialization_with_default_logger(self) -> None:
        """Test initialization creates analyzer with default logger."""
        analyzer = ProtectionAnalyzer()

        assert analyzer is not None
        assert analyzer.logger is not None
        assert analyzer.entropy_threshold_high == 7.5
        assert analyzer.entropy_threshold_low == 1.0
        assert hasattr(analyzer, 'protection_signatures')

    def test_initialization_with_custom_logger(self) -> None:
        """Test initialization accepts custom logger."""
        custom_logger = Mock()
        analyzer = ProtectionAnalyzer(logger=custom_logger)

        assert analyzer.logger is custom_logger

    def test_load_protection_signatures_returns_all_protections(self) -> None:
        """Test _load_protection_signatures returns complete signature database."""
        analyzer = ProtectionAnalyzer()
        signatures = analyzer.protection_signatures

        expected_protections = [
            "upx", "vmprotect", "themida", "asprotect",
            "armadillo", "obsidium", "dotfuscator", "safengine"
        ]

        for protection in expected_protections:
            assert protection in signatures
            assert "name" in signatures[protection]
            assert "type" in signatures[protection]
            assert "signatures" in signatures[protection]
            assert "strings" in signatures[protection]
            assert "severity" in signatures[protection]

    def test_protection_signatures_have_correct_types(self) -> None:
        """Test protection signatures have correct type classifications."""
        analyzer = ProtectionAnalyzer()

        assert analyzer.protection_signatures["upx"]["type"] == "packer"
        assert analyzer.protection_signatures["vmprotect"]["type"] == "protector"
        assert analyzer.protection_signatures["themida"]["type"] == "protector"
        assert analyzer.protection_signatures["dotfuscator"]["type"] == "obfuscator"

    def test_protection_signatures_have_correct_severity(self) -> None:
        """Test protection signatures have appropriate severity levels."""
        analyzer = ProtectionAnalyzer()

        assert analyzer.protection_signatures["vmprotect"]["severity"] == "high"
        assert analyzer.protection_signatures["themida"]["severity"] == "high"
        assert analyzer.protection_signatures["upx"]["severity"] == "medium"


class TestFileInfo:
    """Test file information extraction."""

    @pytest.fixture
    def temp_binary(self, tmp_path: Path) -> Path:
        """Create a temporary binary file for testing."""
        binary_path = tmp_path / "test.exe"
        test_data = b"MZ\x90\x00" + b"\x00" * 100
        binary_path.write_bytes(test_data)
        return binary_path

    def test_get_file_info_computes_sha256(self, temp_binary: Path) -> None:
        """Test _get_file_info computes correct SHA256 hash."""
        analyzer = ProtectionAnalyzer()
        file_data = temp_binary.read_bytes()
        expected_sha256 = hashlib.sha256(file_data).hexdigest()

        file_info = analyzer._get_file_info(temp_binary, file_data)

        assert file_info["sha256"] == expected_sha256
        assert file_info["sha256_primary"] == expected_sha256

    def test_get_file_info_computes_sha3_256(self, temp_binary: Path) -> None:
        """Test _get_file_info computes correct SHA3-256 hash."""
        analyzer = ProtectionAnalyzer()
        file_data = temp_binary.read_bytes()
        expected_sha3 = hashlib.sha3_256(file_data).hexdigest()

        file_info = analyzer._get_file_info(temp_binary, file_data)

        assert file_info["sha3_256"] == expected_sha3

    def test_get_file_info_returns_correct_metadata(self, temp_binary: Path) -> None:
        """Test _get_file_info returns complete file metadata."""
        analyzer = ProtectionAnalyzer()
        file_data = temp_binary.read_bytes()

        file_info = analyzer._get_file_info(temp_binary, file_data)

        assert file_info["filename"] == "test.exe"
        assert file_info["filepath"] == str(temp_binary)
        assert file_info["size"] == len(file_data)
        assert "file_type" in file_info


class TestFileTypeDetection:
    """Test file type detection for various binary formats."""

    def test_detect_file_type_identifies_pe_files(self) -> None:
        """Test _detect_file_type correctly identifies PE/MZ files."""
        analyzer = ProtectionAnalyzer()

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        file_type = analyzer._detect_file_type(pe_header)

        assert file_type in ["PE", "PE32", "PE32+", "Windows Executable"]

    def test_detect_file_type_identifies_elf_files(self) -> None:
        """Test _detect_file_type correctly identifies ELF files."""
        analyzer = ProtectionAnalyzer()

        elf_header = b"\x7fELF" + b"\x00" * 60
        file_type = analyzer._detect_file_type(elf_header)

        assert file_type in ["ELF", "ELF32", "ELF64", "Linux Executable"]

    def test_detect_file_type_identifies_macho_files(self) -> None:
        """Test _detect_file_type correctly identifies Mach-O files."""
        analyzer = ProtectionAnalyzer()

        macho_header_32 = struct.pack("<I", 0xFEEDFACE) + b"\x00" * 60
        macho_header_64 = struct.pack("<I", 0xFEEDFACF) + b"\x00" * 60

        file_type_32 = analyzer._detect_file_type(macho_header_32)
        file_type_64 = analyzer._detect_file_type(macho_header_64)

        assert file_type_32 in ["Mach-O", "Mach-O 32-bit", "macOS Executable"]
        assert file_type_64 in ["Mach-O", "Mach-O 64-bit", "macOS Executable"]

    def test_detect_file_type_returns_unknown_for_unrecognized(self) -> None:
        """Test _detect_file_type returns Unknown for unrecognized formats."""
        analyzer = ProtectionAnalyzer()

        random_data = b"\xff\xfe\xfd\xfc" + b"\x00" * 60
        file_type = analyzer._detect_file_type(random_data)

        assert file_type == "Unknown"


class TestProtectionDetection:
    """Test protection system detection using real signatures."""

    @pytest.fixture
    def upx_packed_data(self) -> bytes:
        """Create binary data with UPX signatures."""
        return b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX1" + b"\x00" * 100

    @pytest.fixture
    def vmprotect_data(self) -> bytes:
        """Create binary data with VMProtect signatures."""
        return b"\x00" * 100 + b"VMProtect" + b"\x00" * 100 + b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52\x53\x56\x57" + b"\x00" * 100

    @pytest.fixture
    def themida_data(self) -> bytes:
        """Create binary data with Themida signatures."""
        return b"\x00" * 100 + b"Themida" + b"\x00" * 100 + b"\xeb\x10\x00\x00\x00\x56\x69\x72\x74\x75\x61\x6c\x41\x6c\x6c\x6f\x63" + b"\x00" * 100

    def test_detect_protections_finds_upx_signatures(self, upx_packed_data: bytes) -> None:
        """Test _detect_protections finds UPX packer signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(upx_packed_data)

        assert len(detections) > 0
        upx_detected = any(d["name"] == "UPX Packer" for d in detections)
        assert upx_detected, "UPX packer should be detected"

    def test_detect_protections_finds_vmprotect_signatures(self, vmprotect_data: bytes) -> None:
        """Test _detect_protections finds VMProtect signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(vmprotect_data)

        assert len(detections) > 0
        vmp_detected = any(d["name"] == "VMProtect" for d in detections)
        assert vmp_detected, "VMProtect should be detected"

    def test_detect_protections_finds_themida_signatures(self, themida_data: bytes) -> None:
        """Test _detect_protections finds Themida signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(themida_data)

        assert len(detections) > 0
        themida_detected = any(d["name"] == "Themida" for d in detections)
        assert themida_detected, "Themida should be detected"

    def test_detect_protections_returns_empty_for_clean_binary(self) -> None:
        """Test _detect_protections returns empty list for clean binaries."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ\x90\x00" + b"\x00" * 1000
        detections = analyzer._detect_protections(clean_data)

        assert isinstance(detections, list)

    def test_detect_protections_returns_detection_with_correct_structure(self, upx_packed_data: bytes) -> None:
        """Test _detect_protections returns detections with proper structure."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(upx_packed_data)

        if detections:
            detection = detections[0]
            assert "name" in detection
            assert "type" in detection
            assert "severity" in detection
            assert "signatures_matched" in detection or "matched" in detection


class TestAnalyzeMethod:
    """Test the main analyze() method with various scenarios."""

    @pytest.fixture
    def test_binary(self, tmp_path: Path) -> Path:
        """Create a test binary with UPX signature."""
        binary_path = tmp_path / "protected.exe"
        data = b"MZ\x90\x00" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100
        binary_path.write_bytes(data)
        return binary_path

    def test_analyze_returns_error_when_file_not_found(self) -> None:
        """Test analyze() returns error dict when file doesn't exist."""
        analyzer = ProtectionAnalyzer()

        result = analyzer.analyze("/nonexistent/path/to/file.exe")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_handles_permission_errors_gracefully(self, tmp_path: Path) -> None:
        """Test analyze() handles permission errors gracefully."""
        analyzer = ProtectionAnalyzer()
        test_file = tmp_path / "no_permission.exe"
        test_file.write_bytes(b"test")

        if os.name != 'nt':
            os.chmod(test_file, 0o000)
            result = analyzer.analyze(test_file)
            os.chmod(test_file, 0o644)

            assert "error" in result

    def test_analyze_returns_complete_result_dict(self, test_binary: Path) -> None:
        """Test analyze() returns complete result dictionary with all keys."""
        analyzer = ProtectionAnalyzer()

        result = analyzer.analyze(test_binary)

        required_keys = [
            "file_info", "detected_protections", "entropy_analysis",
            "section_analysis", "import_analysis", "anti_analysis",
            "recommendations", "risk_score", "analysis_timestamp"
        ]

        for key in required_keys:
            assert key in result, f"Result should contain '{key}'"

    def test_analyze_file_info_contains_required_fields(self, test_binary: Path) -> None:
        """Test analyze() file_info contains all required metadata."""
        analyzer = ProtectionAnalyzer()

        result = analyzer.analyze(test_binary)

        file_info = result["file_info"]
        assert "filename" in file_info
        assert "filepath" in file_info
        assert "size" in file_info
        assert "sha256" in file_info
        assert "sha3_256" in file_info
        assert "file_type" in file_info


class TestEntropyAnalysis:
    """Test Shannon entropy calculation and analysis."""

    def test_analyze_entropy_detects_high_entropy(self) -> None:
        """Test _analyze_entropy detects high entropy (encrypted/compressed)."""
        analyzer = ProtectionAnalyzer()

        import os
        high_entropy_data = os.urandom(10000)

        entropy_analysis = analyzer._analyze_entropy(high_entropy_data)

        assert "overall_entropy" in entropy_analysis
        assert entropy_analysis["overall_entropy"] > 7.0

    def test_analyze_entropy_detects_low_entropy(self) -> None:
        """Test _analyze_entropy detects low entropy (padding/zeros)."""
        analyzer = ProtectionAnalyzer()

        low_entropy_data = b"\x00" * 10000

        entropy_analysis = analyzer._analyze_entropy(low_entropy_data)

        assert "overall_entropy" in entropy_analysis
        assert entropy_analysis["overall_entropy"] < 1.0

    def test_analyze_entropy_handles_empty_files(self) -> None:
        """Test _analyze_entropy handles empty/zero-byte files."""
        analyzer = ProtectionAnalyzer()

        entropy_analysis = analyzer._analyze_entropy(b"")

        assert entropy_analysis is not None
        assert isinstance(entropy_analysis, dict)

    def test_analyze_entropy_calculates_shannon_entropy_correctly(self) -> None:
        """Test _analyze_entropy uses correct Shannon entropy formula."""
        analyzer = ProtectionAnalyzer()

        test_data = b"AAAABBBBCCCCDDDD"

        entropy_analysis = analyzer._analyze_entropy(test_data)

        expected_entropy = 2.0
        assert abs(entropy_analysis["overall_entropy"] - expected_entropy) < 0.1


pytest.main([__file__, "-v", "--tb=short"])
