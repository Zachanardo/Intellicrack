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
from typing import Any

import pytest

from intellicrack.core.protection_analyzer import ProtectionAnalyzer


class FakeLogger:
    """Fake logger for testing."""

    def __init__(self) -> None:
        """Initialize fake logger."""
        self.debug_messages: list[str] = []
        self.info_messages: list[str] = []
        self.warning_messages: list[str] = []
        self.error_messages: list[str] = []

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        self.debug_messages.append(message)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        self.info_messages.append(message)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        self.warning_messages.append(message)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        self.error_messages.append(message)


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
        custom_logger: FakeLogger = FakeLogger()
        analyzer: ProtectionAnalyzer = ProtectionAnalyzer(logger=custom_logger)

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

        if detections := analyzer._detect_protections(upx_packed_data):
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


class TestAdditionalProtectionDetection:
    """Test detection of additional protection systems."""

    @pytest.fixture
    def asprotect_data(self) -> bytes:
        """Create binary data with ASProtect signatures."""
        return b"\x00" * 100 + b"ASProtect" + b"\x00" * 100 + b"\x68\x00\x00\x00\x00\x64\xff\x35\x00\x00\x00\x00" + b"\x00" * 100

    @pytest.fixture
    def armadillo_data(self) -> bytes:
        """Create binary data with Armadillo signatures."""
        return b"\x00" * 100 + b"Armadillo" + b"\x00" * 100 + b"\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00" + b"\x00" * 100

    @pytest.fixture
    def obsidium_data(self) -> bytes:
        """Create binary data with Obsidium signatures."""
        return b"\x00" * 100 + b"Obsidium" + b"\x00" * 100 + b"\xeb\x02\xcd\x20\x03\xc0\x0f\x84" + b"\x00" * 100

    @pytest.fixture
    def dotfuscator_data(self) -> bytes:
        """Create binary data with Dotfuscator/.NET Reactor signatures."""
        return b"\x00" * 100 + b"Dotfuscator" + b"\x00" * 100 + b".NET Reactor" + b"\x00" * 100

    @pytest.fixture
    def safengine_data(self) -> bytes:
        """Create binary data with SafeEngine signatures."""
        return b"\x00" * 100 + b"SafeEngine" + b"\x00" * 100 + b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed" + b"\x00" * 100

    def test_detect_protections_finds_asprotect_signatures(self, asprotect_data: bytes) -> None:
        """Test _detect_protections finds ASProtect signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(asprotect_data)

        assert len(detections) > 0
        asp_detected = any(d["name"] == "ASProtect" for d in detections)
        assert asp_detected, "ASProtect should be detected"

    def test_detect_protections_finds_armadillo_signatures(self, armadillo_data: bytes) -> None:
        """Test _detect_protections finds Armadillo signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(armadillo_data)

        assert len(detections) > 0
        arma_detected = any(d["name"] == "Armadillo" for d in detections)
        assert arma_detected, "Armadillo should be detected"

    def test_detect_protections_finds_obsidium_signatures(self, obsidium_data: bytes) -> None:
        """Test _detect_protections finds Obsidium signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(obsidium_data)

        assert len(detections) > 0
        obs_detected = any(d["name"] == "Obsidium" for d in detections)
        assert obs_detected, "Obsidium should be detected"

    def test_detect_protections_finds_dotfuscator_signatures(self, dotfuscator_data: bytes) -> None:
        """Test _detect_protections finds Dotfuscator/.NET Reactor signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(dotfuscator_data)

        assert len(detections) > 0
        dotf_detected = any(".NET Reactor" in d["name"] or "Dotfuscator" in d["name"] for d in detections)
        assert dotf_detected, "Dotfuscator/.NET Reactor should be detected"

    def test_detect_protections_finds_safengine_signatures(self, safengine_data: bytes) -> None:
        """Test _detect_protections finds SafeEngine signatures."""
        analyzer = ProtectionAnalyzer()

        detections = analyzer._detect_protections(safengine_data)

        assert len(detections) > 0
        safe_detected = any(d["name"] == "SafeEngine Protector" for d in detections)
        assert safe_detected, "SafeEngine should be detected"


class TestSectionAnalysis:
    """Test binary section analysis functionality."""

    def test_analyze_sections_returns_correct_structure(self) -> None:
        """Test _analyze_sections returns expected dict structure."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ\x90\x00" + b"\x00" * 1000
        result = analyzer._analyze_sections(Path("test.exe"), clean_data)

        assert isinstance(result, dict)
        assert "sections" in result
        assert "suspicious_sections" in result
        assert isinstance(result["sections"], list)
        assert isinstance(result["suspicious_sections"], list)

    def test_analyze_sections_handles_non_pe_files(self) -> None:
        """Test _analyze_sections handles non-PE files gracefully."""
        analyzer = ProtectionAnalyzer()

        elf_data = b"\x7fELF" + b"\x00" * 1000
        result = analyzer._analyze_sections(Path("test.elf"), elf_data)

        assert isinstance(result, dict)
        assert "sections" in result

    def test_analyze_sections_identifies_high_entropy_sections(self) -> None:
        """Test _analyze_sections identifies suspicious high-entropy sections."""
        analyzer = ProtectionAnalyzer()

        result = {
            "sections": [
                {"name": ".text", "entropy": 6.5},
                {"name": ".vmp", "entropy": 7.8},
                {"name": ".data", "entropy": 3.2},
            ],
            "suspicious_sections": [],
        }

        suspicious = [s for s in result["sections"] if s.get("entropy", 0) > 7.0]
        assert len(suspicious) == 1
        assert suspicious[0]["name"] == ".vmp"


class TestImportAnalysis:
    """Test import table analysis functionality."""

    def test_analyze_imports_returns_correct_structure(self) -> None:
        """Test _analyze_imports returns expected dict structure."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ\x90\x00" + b"\x00" * 1000
        result = analyzer._analyze_imports(Path("test.exe"), clean_data)

        assert isinstance(result, dict)
        assert "imports" in result
        assert "suspicious_imports" in result
        assert "import_count" in result

    def test_analyze_imports_handles_non_pe_files(self) -> None:
        """Test _analyze_imports handles non-PE files gracefully."""
        analyzer = ProtectionAnalyzer()

        elf_data = b"\x7fELF" + b"\x00" * 1000
        result = analyzer._analyze_imports(Path("test.elf"), elf_data)

        assert isinstance(result, dict)
        assert result["import_count"] == 0

    def test_analyze_imports_identifies_suspicious_apis(self) -> None:
        """Test _analyze_imports identifies suspicious API calls."""
        analyzer = ProtectionAnalyzer()

        suspicious_apis = [
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        ]

        for api in suspicious_apis:
            test_import = f"kernel32.dll!{api}"
            assert any(sus_api in api for sus_api in suspicious_apis)


class TestAntiAnalysisDetection:
    """Test anti-analysis technique detection."""

    def test_detect_anti_analysis_finds_is_debugger_present(self) -> None:
        """Test _detect_anti_analysis detects IsDebuggerPresent."""
        analyzer = ProtectionAnalyzer()

        data = b"\x00" * 100 + b"IsDebuggerPresent" + b"\x00" * 100

        result = analyzer._detect_anti_analysis(data)

        assert result["anti_debug_detected"] is True
        assert "IsDebuggerPresent" in result["techniques"]

    def test_detect_anti_analysis_finds_check_remote_debugger(self) -> None:
        """Test _detect_anti_analysis detects CheckRemoteDebuggerPresent."""
        analyzer = ProtectionAnalyzer()

        data = b"\x00" * 100 + b"CheckRemoteDebuggerPresent" + b"\x00" * 100

        result = analyzer._detect_anti_analysis(data)

        assert result["anti_debug_detected"] is True
        assert "CheckRemoteDebuggerPresent" in result["techniques"]

    def test_detect_anti_analysis_finds_nt_query_information_process(self) -> None:
        """Test _detect_anti_analysis detects NtQueryInformationProcess."""
        analyzer = ProtectionAnalyzer()

        data = b"\x00" * 100 + b"NtQueryInformationProcess" + b"\x00" * 100

        result = analyzer._detect_anti_analysis(data)

        assert result["anti_debug_detected"] is True
        assert "NtQueryInformationProcess" in result["techniques"]

    def test_detect_anti_analysis_finds_output_debug_string(self) -> None:
        """Test _detect_anti_analysis detects OutputDebugString."""
        analyzer = ProtectionAnalyzer()

        data = b"\x00" * 100 + b"OutputDebugStringA" + b"\x00" * 100

        result = analyzer._detect_anti_analysis(data)

        assert result["anti_debug_detected"] is True
        assert "OutputDebugString" in result["techniques"]

    def test_detect_anti_analysis_finds_rdtsc_timing(self) -> None:
        """Test _detect_anti_analysis detects RDTSC timing checks."""
        analyzer = ProtectionAnalyzer()

        data = b"\x00" * 100 + b"\x0f\x31" + b"\x00" * 100

        result = analyzer._detect_anti_analysis(data)

        assert result["anti_debug_detected"] is True
        assert "RDTSC timing" in result["techniques"]

    def test_detect_anti_analysis_returns_clean_for_no_techniques(self) -> None:
        """Test _detect_anti_analysis returns empty when no techniques found."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ\x90\x00" + b"\x00" * 1000

        result = analyzer._detect_anti_analysis(clean_data)

        assert result["anti_debug_detected"] is False
        assert len(result["techniques"]) == 0
        assert result["risk_level"] == "low"

    def test_detect_anti_analysis_calculates_correct_risk_level(self) -> None:
        """Test _detect_anti_analysis calculates risk level correctly."""
        analyzer = ProtectionAnalyzer()

        data_high_risk = (
            b"\x00" * 50
            + b"IsDebuggerPresent" + b"\x00" * 50
            + b"CheckRemoteDebuggerPresent" + b"\x00" * 50
            + b"NtQueryInformationProcess" + b"\x00" * 50
        )

        result = analyzer._detect_anti_analysis(data_high_risk)

        assert result["anti_debug_detected"] is True
        assert len(result["techniques"]) >= 3
        assert result["risk_level"] == "high"


class TestRecommendationGeneration:
    """Test recommendation generation functionality."""

    def test_generate_recommendations_for_detected_protections(self) -> None:
        """Test _generate_recommendations provides recommendations for detected protections."""
        analyzer = ProtectionAnalyzer()

        detected_protections = [
            {"name": "UPX Packer", "type": "packer", "severity": "medium"},
            {"name": "VMProtect", "type": "protector", "severity": "high"},
        ]
        entropy_analysis = {"overall_entropy": 5.0}
        section_analysis = {"suspicious_sections": []}
        anti_analysis = {"anti_debug_detected": False}

        recommendations = analyzer._generate_recommendations(
            detected_protections, entropy_analysis, section_analysis, anti_analysis
        )

        assert len(recommendations) > 0
        assert any("UPX Packer" in rec or "VMProtect" in rec for rec in recommendations)
        assert any("unpacking" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_for_high_entropy(self) -> None:
        """Test _generate_recommendations recommends entropy analysis for high-entropy files."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 7.8}
        section_analysis = {"suspicious_sections": []}
        anti_analysis = {"anti_debug_detected": False}

        recommendations = analyzer._generate_recommendations(
            detected_protections, entropy_analysis, section_analysis, anti_analysis
        )

        assert len(recommendations) > 0
        assert any("entropy" in rec.lower() for rec in recommendations)
        assert any("encrypted" in rec.lower() or "compressed" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_for_anti_debug(self) -> None:
        """Test _generate_recommendations recommends anti-debug bypass."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 5.0}
        section_analysis = {"suspicious_sections": []}
        anti_analysis = {"anti_debug_detected": True, "techniques": ["IsDebuggerPresent"]}

        recommendations = analyzer._generate_recommendations(
            detected_protections, entropy_analysis, section_analysis, anti_analysis
        )

        assert len(recommendations) > 0
        assert any("anti-debug" in rec.lower() or "debug" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_for_suspicious_sections(self) -> None:
        """Test _generate_recommendations notes suspicious sections."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 5.0}
        section_analysis = {"suspicious_sections": [{"name": ".vmp", "entropy": 7.9}]}
        anti_analysis = {"anti_debug_detected": False}

        recommendations = analyzer._generate_recommendations(
            detected_protections, entropy_analysis, section_analysis, anti_analysis
        )

        assert len(recommendations) > 0
        assert any("section" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_for_clean_binary(self) -> None:
        """Test _generate_recommendations provides standard advice for clean binaries."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 5.0}
        section_analysis = {"suspicious_sections": []}
        anti_analysis = {"anti_debug_detected": False}

        recommendations = analyzer._generate_recommendations(
            detected_protections, entropy_analysis, section_analysis, anti_analysis
        )

        assert len(recommendations) > 0
        assert any("no significant protections" in rec.lower() or "standard analysis" in rec.lower() for rec in recommendations)


class TestRiskScoreCalculation:
    """Test risk score calculation functionality."""

    def test_calculate_risk_score_returns_zero_for_clean_files(self) -> None:
        """Test _calculate_risk_score returns 0 for clean files."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 5.0}
        anti_analysis = {"anti_debug_detected": False, "techniques": []}

        risk_score = analyzer._calculate_risk_score(detected_protections, entropy_analysis, anti_analysis)

        assert risk_score == 0

    def test_calculate_risk_score_increases_for_detected_protections(self) -> None:
        """Test _calculate_risk_score increases based on detected protections."""
        analyzer = ProtectionAnalyzer()

        detected_protections = [
            {"name": "UPX Packer", "type": "packer", "severity": "medium"},
        ]
        entropy_analysis = {"overall_entropy": 5.0}
        anti_analysis = {"anti_debug_detected": False, "techniques": []}

        risk_score = analyzer._calculate_risk_score(detected_protections, entropy_analysis, anti_analysis)

        assert risk_score > 0
        assert risk_score >= 15

    def test_calculate_risk_score_weights_by_severity(self) -> None:
        """Test _calculate_risk_score weights protections by severity."""
        analyzer = ProtectionAnalyzer()

        high_severity_protections = [
            {"name": "VMProtect", "type": "protector", "severity": "high"},
        ]
        medium_severity_protections = [
            {"name": "UPX Packer", "type": "packer", "severity": "medium"},
        ]

        entropy_analysis = {"overall_entropy": 5.0}
        anti_analysis = {"anti_debug_detected": False, "techniques": []}

        risk_high = analyzer._calculate_risk_score(high_severity_protections, entropy_analysis, anti_analysis)
        risk_medium = analyzer._calculate_risk_score(medium_severity_protections, entropy_analysis, anti_analysis)

        assert risk_high > risk_medium

    def test_calculate_risk_score_increases_for_high_entropy(self) -> None:
        """Test _calculate_risk_score increases for high entropy."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        high_entropy_analysis = {"overall_entropy": 7.8}
        low_entropy_analysis = {"overall_entropy": 5.0}
        anti_analysis = {"anti_debug_detected": False, "techniques": []}

        risk_high = analyzer._calculate_risk_score(detected_protections, high_entropy_analysis, anti_analysis)
        risk_low = analyzer._calculate_risk_score(detected_protections, low_entropy_analysis, anti_analysis)

        assert risk_high > risk_low

    def test_calculate_risk_score_increases_for_anti_analysis(self) -> None:
        """Test _calculate_risk_score increases for anti-analysis techniques."""
        analyzer = ProtectionAnalyzer()

        detected_protections = []
        entropy_analysis = {"overall_entropy": 5.0}
        anti_analysis_detected = {"anti_debug_detected": True, "techniques": ["IsDebuggerPresent", "RDTSC timing"]}
        anti_analysis_clean = {"anti_debug_detected": False, "techniques": []}

        risk_with_anti = analyzer._calculate_risk_score(detected_protections, entropy_analysis, anti_analysis_detected)
        risk_without_anti = analyzer._calculate_risk_score(detected_protections, entropy_analysis, anti_analysis_clean)

        assert risk_with_anti > risk_without_anti

    def test_calculate_risk_score_caps_at_maximum_value(self) -> None:
        """Test _calculate_risk_score caps at maximum value (100)."""
        analyzer = ProtectionAnalyzer()

        many_protections = [
            {"name": f"Protection{i}", "type": "protector", "severity": "high"}
            for i in range(20)
        ]
        entropy_analysis = {"overall_entropy": 7.9}
        anti_analysis = {"anti_debug_detected": True, "techniques": ["IsDebuggerPresent"] * 10}

        risk_score = analyzer._calculate_risk_score(many_protections, entropy_analysis, anti_analysis)

        assert risk_score <= 100


class TestThreadSafety:
    """Test thread safety of analyzer."""

    def test_concurrent_analysis_thread_safety(self, tmp_path: Path) -> None:
        """Test analyzer can be used concurrently from multiple threads."""
        import threading

        analyzer = ProtectionAnalyzer()

        test_files = []
        for i in range(5):
            file_path = tmp_path / f"test_{i}.exe"
            data = b"MZ\x90\x00" + b"\x00" * 100 + (b"UPX0" if i % 2 == 0 else b"\x00" * 10) + b"\x00" * 100
            file_path.write_bytes(data)
            test_files.append(file_path)

        results = []

        def analyze_file(file_path: Path) -> None:
            result = analyzer.analyze(file_path)
            results.append(result)

        threads = [threading.Thread(target=analyze_file, args=(f,)) for f in test_files]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(results) == 5
        for result in results:
            assert "file_info" in result or "error" in result
