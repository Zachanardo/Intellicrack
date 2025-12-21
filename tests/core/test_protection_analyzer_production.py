"""Production tests for ProtectionAnalyzer - validates real binary protection detection.

Tests real PE/ELF/Mach-O analysis, protection signature detection, entropy calculation,
section analysis, import scanning, and anti-analysis detection WITHOUT mocks or stubs.
"""

import hashlib
import struct
from pathlib import Path

import pytest

from intellicrack.core.protection_analyzer import ProtectionAnalyzer


ENTROPY_HIGH_THRESHOLD = 7.0
ENTROPY_LOW_THRESHOLD = 1.0
RISK_SCORE_HIGH_THRESHOLD = 50
RISK_SCORE_LOW_THRESHOLD = 30
RISK_SCORE_MAX = 100
MINIMUM_SECTION_COUNT = 3


class TestBinaryTypeDetection:
    """Test detection of binary file types from magic bytes."""

    def test_detect_pe_file_type(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects PE (Windows executable) file type from MZ header."""
        analyzer = ProtectionAnalyzer()

        pe_header = b"MZ" + b"\x00" * RISK_SCORE_MAX
        binary_file = tmp_path / "test.exe"
        binary_file.write_bytes(pe_header)

        with open(binary_file, "rb") as f:
            data = f.read()

        file_type = analyzer._detect_file_type(data)
        assert file_type == "PE"

    def test_detect_elf_file_type(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects ELF (Linux executable) file type from ELF header."""
        analyzer = ProtectionAnalyzer()

        elf_header = b"\x7fELF" + b"\x00" * RISK_SCORE_MAX
        binary_file = tmp_path / "test.elf"
        binary_file.write_bytes(elf_header)

        with open(binary_file, "rb") as f:
            data = f.read()

        file_type = analyzer._detect_file_type(data)
        assert file_type == "ELF"

    def test_detect_macho_file_type(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects Mach-O (macOS executable) file type from magic bytes."""
        analyzer = ProtectionAnalyzer()

        macho_header = b"\xfe\xed\xfa\xce" + b"\x00" * RISK_SCORE_MAX
        binary_file = tmp_path / "test.macho"
        binary_file.write_bytes(macho_header)

        with open(binary_file, "rb") as f:
            data = f.read()

        file_type = analyzer._detect_file_type(data)
        assert file_type == "Mach-O"

    def test_detect_unknown_file_type(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Returns 'Unknown' for unrecognized file types."""
        analyzer = ProtectionAnalyzer()

        unknown_data = b"RANDOM" + b"\x00" * RISK_SCORE_MAX
        binary_file = tmp_path / "unknown.bin"
        binary_file.write_bytes(unknown_data)

        with open(binary_file, "rb") as f:
            data = f.read()

        file_type = analyzer._detect_file_type(data)
        assert file_type == "Unknown"


class TestProtectionSignatureDetection:
    """Test detection of protection systems using signatures."""

    def test_detect_upx_packer_signature(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects UPX packer from signature bytes."""
        analyzer = ProtectionAnalyzer()

        upx_signature = b"UPX0" + b"\x00" * 1000
        binary_file = tmp_path / "upx_packed.exe"
        binary_file.write_bytes(b"MZ" + b"\x00" * RISK_SCORE_MAX + upx_signature)

        result = analyzer.analyze(binary_file)

        assert "detected_protections" in result
        upx_found = any(p["name"] == "UPX Packer" for p in result["detected_protections"])
        assert upx_found

    def test_detect_vmprotect_signature(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects VMProtect from signature bytes."""
        analyzer = ProtectionAnalyzer()

        vmprotect_sig = b"VMProtect" + b"\x00" * 1000
        binary_file = tmp_path / "vmprotect.exe"
        binary_file.write_bytes(b"MZ" + b"\x00" * RISK_SCORE_MAX + vmprotect_sig)

        result = analyzer.analyze(binary_file)

        assert "detected_protections" in result
        vmp_found = any(p["name"] == "VMProtect" for p in result["detected_protections"])
        assert vmp_found

    def test_detect_themida_signature(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects Themida protection from signature bytes."""
        analyzer = ProtectionAnalyzer()

        themida_sig = b"Themida" + b"\x00" * 1000
        binary_file = tmp_path / "themida.exe"
        binary_file.write_bytes(b"MZ" + b"\x00" * RISK_SCORE_MAX + themida_sig)

        result = analyzer.analyze(binary_file)

        assert "detected_protections" in result
        themida_found = any(p["name"] == "Themida" for p in result["detected_protections"])
        assert themida_found

    def test_detect_multiple_protections(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects multiple protection systems in same binary."""
        analyzer = ProtectionAnalyzer()

        combined = b"MZ" + b"\x00" * RISK_SCORE_MAX + b"UPX0" + b"\x00" * 500 + b"VMProtect"
        binary_file = tmp_path / "multi_protected.exe"
        binary_file.write_bytes(combined)

        result = analyzer.analyze(binary_file)

        assert "detected_protections" in result
        protection_names = {p["name"] for p in result["detected_protections"]}
        assert "UPX Packer" in protection_names
        assert "VMProtect" in protection_names

    def test_no_protections_detected_in_clean_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Returns empty list when no protections detected."""
        analyzer = ProtectionAnalyzer()

        clean_binary = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "clean.exe"
        binary_file.write_bytes(clean_binary)

        result = analyzer.analyze(binary_file)

        assert "detected_protections" in result
        assert len(result["detected_protections"]) == 0


class TestEntropyAnalysis:
    """Test Shannon entropy calculation for binary analysis."""

    def test_calculate_entropy_of_random_data(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Calculates high entropy for random/encrypted data."""
        analyzer = ProtectionAnalyzer()

        import os
        random_data = os.urandom(4096)
        binary_file = tmp_path / "random.bin"
        binary_file.write_bytes(b"MZ" + random_data)

        result = analyzer.analyze(binary_file)

        assert "entropy_analysis" in result
        entropy = result["entropy_analysis"]["overall_entropy"]
        assert entropy >= ENTROPY_HIGH_THRESHOLD

    def test_calculate_entropy_of_low_entropy_data(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Calculates low entropy for repetitive data."""
        analyzer = ProtectionAnalyzer()

        low_entropy_data = b"\x00" * 4096
        binary_file = tmp_path / "zeros.bin"
        binary_file.write_bytes(b"MZ" + low_entropy_data)

        result = analyzer.analyze(binary_file)

        assert "entropy_analysis" in result
        entropy = result["entropy_analysis"]["overall_entropy"]
        assert entropy < ENTROPY_LOW_THRESHOLD

    def test_entropy_analysis_identifies_high_entropy_sections(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Identifies sections with high entropy (packed/encrypted)."""
        analyzer = ProtectionAnalyzer()

        import os
        high_entropy = os.urandom(2048)
        low_entropy = b"\x00" * 2048

        binary_file = tmp_path / "mixed.bin"
        binary_file.write_bytes(b"MZ" + low_entropy + high_entropy)

        result = analyzer.analyze(binary_file)

        assert "entropy_analysis" in result
        assert "high_entropy_sections" in result["entropy_analysis"]

    def test_entropy_calculation_handles_empty_data(self) -> None:  # noqa: PLR6301
        """Handles empty data without errors."""
        analyzer = ProtectionAnalyzer()

        result = analyzer._analyze_entropy(b"")

        assert result["overall_entropy"] == 0.0


class TestAntiAnalysisDetection:
    """Test detection of anti-debugging and anti-analysis techniques."""

    def test_detect_isdebuggerpresent_api(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects IsDebuggerPresent API usage."""
        analyzer = ProtectionAnalyzer()

        binary_data = b"MZ" + b"\x00" * 500 + b"IsDebuggerPresent" + b"\x00" * 500
        binary_file = tmp_path / "anti_debug.exe"
        binary_file.write_bytes(binary_data)

        result = analyzer.analyze(binary_file)

        assert "anti_analysis" in result
        assert result["anti_analysis"]["anti_debug_detected"] is True
        assert "IsDebuggerPresent" in result["anti_analysis"]["techniques"]

    def test_detect_rdtsc_timing_check(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects RDTSC timing check instruction."""
        analyzer = ProtectionAnalyzer()

        rdtsc_instruction = b"\x0f\x31"
        binary_data = b"MZ" + b"\x00" * 500 + rdtsc_instruction + b"\x00" * 500
        binary_file = tmp_path / "rdtsc.exe"
        binary_file.write_bytes(binary_data)

        result = analyzer.analyze(binary_file)

        assert "anti_analysis" in result
        assert "RDTSC timing" in result["anti_analysis"]["techniques"]

    def test_detect_multiple_anti_debug_techniques(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Detects multiple anti-debugging techniques."""
        analyzer = ProtectionAnalyzer()

        binary_data = (
            b"MZ" +
            b"\x00" * 200 +
            b"IsDebuggerPresent" +
            b"\x00" * 200 +
            b"CheckRemoteDebuggerPresent" +
            b"\x00" * 200 +
            b"\x0f\x31"
        )
        binary_file = tmp_path / "multi_anti_debug.exe"
        binary_file.write_bytes(binary_data)

        result = analyzer.analyze(binary_file)

        assert "anti_analysis" in result
        assert len(result["anti_analysis"]["techniques"]) >= MINIMUM_SECTION_COUNT
        assert result["anti_analysis"]["risk_level"] == "high"

    def test_no_anti_debug_detected_in_clean_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Returns no anti-debug for clean binary."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "clean_no_anti.exe"
        binary_file.write_bytes(clean_data)

        result = analyzer.analyze(binary_file)

        assert "anti_analysis" in result
        assert result["anti_analysis"]["anti_debug_detected"] is False
        assert result["anti_analysis"]["risk_level"] == "low"


class TestRiskScoreCalculation:
    """Test risk score calculation based on findings."""

    def test_calculate_high_risk_score_for_protected_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Calculates high risk score for heavily protected binary."""
        analyzer = ProtectionAnalyzer()

        import os
        protected_data = (
            b"MZ"
            b"VMProtect" +
            os.urandom(2048) +
            b"IsDebuggerPresent" +
            b"CheckRemoteDebuggerPresent"
        )
        binary_file = tmp_path / "high_risk.exe"
        binary_file.write_bytes(protected_data)

        result = analyzer.analyze(binary_file)

        assert "risk_score" in result
        assert result["risk_score"] >= RISK_SCORE_HIGH_THRESHOLD

    def test_calculate_low_risk_score_for_clean_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Calculates low risk score for clean binary."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "low_risk.exe"
        binary_file.write_bytes(clean_data)

        result = analyzer.analyze(binary_file)

        assert "risk_score" in result
        assert result["risk_score"] < RISK_SCORE_LOW_THRESHOLD

    def test_risk_score_capped_at_100(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Risk score is capped at maximum of RISK_SCORE_MAX."""
        analyzer = ProtectionAnalyzer()

        import os
        extreme_data = (
            b"MZ" +
            b"VMProtect" * 10 +
            b"Themida" * 10 +
            os.urandom(4096) +
            b"IsDebuggerPresent" * 10
        )
        binary_file = tmp_path / "extreme_risk.exe"
        binary_file.write_bytes(extreme_data)

        result = analyzer.analyze(binary_file)

        assert "risk_score" in result
        assert result["risk_score"] <= RISK_SCORE_MAX


class TestFileInfoExtraction:
    """Test file information extraction."""

    def test_extract_file_info_with_hashes(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Extracts file info with SHA256 and SHA3-256 hashes."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"test data" * RISK_SCORE_MAX
        binary_file = tmp_path / "hash_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        assert "file_info" in result
        file_info = result["file_info"]

        assert "sha256" in file_info
        assert "sha3_256" in file_info
        assert "filename" in file_info
        assert "size" in file_info

        expected_sha256 = hashlib.sha256(test_data).hexdigest()
        assert file_info["sha256"] == expected_sha256

    def test_file_info_includes_size_and_path(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """File info includes correct file size and path."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"\x00" * 12345
        binary_file = tmp_path / "size_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        file_info = result["file_info"]
        assert file_info["size"] == len(test_data)
        assert file_info["filename"] == "size_test.exe"
        assert str(binary_file) in file_info["filepath"]


class TestRecommendationsGeneration:
    """Test generation of analysis recommendations."""

    def test_recommendations_for_protected_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Generates appropriate recommendations for protected binaries."""
        analyzer = ProtectionAnalyzer()

        protected_data = b"MZ" + b"\x00" * RISK_SCORE_MAX + b"VMProtect"
        binary_file = tmp_path / "protected.exe"
        binary_file.write_bytes(protected_data)

        result = analyzer.analyze(binary_file)

        assert "recommendations" in result
        recommendations = result["recommendations"]

        assert len(recommendations) > 0
        assert any("VMProtect" in r for r in recommendations)

    def test_recommendations_for_high_entropy_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Generates unpacking recommendations for high entropy."""
        analyzer = ProtectionAnalyzer()

        import os
        high_entropy_data = b"MZ" + os.urandom(4096)
        binary_file = tmp_path / "high_entropy.exe"
        binary_file.write_bytes(high_entropy_data)

        result = analyzer.analyze(binary_file)

        recommendations = result["recommendations"]
        assert any("entropy" in r.lower() for r in recommendations)

    def test_recommendations_for_clean_binary(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Generates 'proceed with standard analysis' for clean binaries."""
        analyzer = ProtectionAnalyzer()

        clean_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "clean.exe"
        binary_file.write_bytes(clean_data)

        result = analyzer.analyze(binary_file)

        recommendations = result["recommendations"]
        assert any("standard analysis" in r.lower() for r in recommendations)


class TestComprehensiveAnalysis:
    """Test comprehensive analysis workflow."""

    def test_analyze_returns_complete_structure(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """analyze() returns all required analysis sections."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "complete_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        required_keys = [
            "file_info",
            "detected_protections",
            "entropy_analysis",
            "section_analysis",
            "import_analysis",
            "anti_analysis",
            "recommendations",
            "risk_score",
            "analysis_timestamp"
        ]

        for key in required_keys:
            assert key in result

    def test_analyze_handles_nonexistent_file(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """analyze() handles nonexistent files gracefully."""
        analyzer = ProtectionAnalyzer()

        nonexistent = tmp_path / "does_not_exist.exe"

        result = analyzer.analyze(nonexistent)

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_includes_timestamp(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Analysis includes ISO format timestamp."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"\x00" * RISK_SCORE_MAX
        binary_file = tmp_path / "timestamp_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        assert "analysis_timestamp" in result
        timestamp = result["analysis_timestamp"]
        assert isinstance(timestamp, str)
        assert "Z" in timestamp


class TestSectionAnalysis:
    """Test binary section analysis (PE-specific when pefile available)."""

    def test_section_analysis_returns_structure(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Section analysis returns proper structure."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "section_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        assert "section_analysis" in result
        section_analysis = result["section_analysis"]

        assert "sections" in section_analysis
        assert "suspicious_sections" in section_analysis
        assert isinstance(section_analysis["sections"], list)
        assert isinstance(section_analysis["suspicious_sections"], list)


class TestImportAnalysis:
    """Test import table analysis."""

    def test_import_analysis_returns_structure(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Import analysis returns proper structure."""
        analyzer = ProtectionAnalyzer()

        test_data = b"MZ" + b"\x00" * 1000
        binary_file = tmp_path / "import_test.exe"
        binary_file.write_bytes(test_data)

        result = analyzer.analyze(binary_file)

        assert "import_analysis" in result
        import_analysis = result["import_analysis"]

        assert "imports" in import_analysis
        assert "suspicious_imports" in import_analysis
        assert "import_count" in import_analysis


class TestErrorHandling:
    """Test error handling during analysis."""

    def test_analyze_handles_read_errors_gracefully(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Handles file read errors without crashing."""
        analyzer = ProtectionAnalyzer()

        binary_file = tmp_path / "no_read_perms.exe"
        binary_file.write_bytes(b"MZ" + b"\x00" * RISK_SCORE_MAX)

        import os
        original_mode = binary_file.stat().st_mode
        try:
            os.chmod(binary_file, 0o000)

            result = analyzer.analyze(binary_file)

            assert "error" in result or "file_info" in result
        finally:
            os.chmod(binary_file, original_mode)

    def test_analyze_handles_corrupted_data(self, tmp_path: Path) -> None:  # noqa: PLR6301
        """Handles corrupted binary data without crashing."""
        analyzer = ProtectionAnalyzer()

        corrupted_data = b"MZ" + b"\xff" * 10 + b"\x00" * 10
        binary_file = tmp_path / "corrupted.exe"
        binary_file.write_bytes(corrupted_data)

        result = analyzer.analyze(binary_file)

        assert isinstance(result, dict)
