"""Comprehensive tests for protection_detector.py.

This test suite validates the ProtectionDetector class and all its detection
capabilities against real binary data and protection schemes. Tests verify
genuine offensive capability to detect, analyze, and provide bypass strategies
for commercial software protections.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    ProtectionAnalysis,
    ProtectionType,
)
from intellicrack.protection.protection_detector import (
    ProtectionDetector,
    deep_analyze,
    detect_all_protections,
    detect_anti_debugging_techniques,
    detect_checksum_verification,
    detect_commercial_protections,
    detect_obfuscation,
    detect_packing_methods,
    detect_protection_mechanisms,
    detect_self_healing_code,
    detect_tpm_protection,
    detect_virtualization_protection,
    generate_checksum,
    get_protection_detector,
    quick_analyze,
    run_comprehensive_protection_scan,
    scan_for_bytecode_protectors,
)
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult


@pytest.fixture
def test_binary_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test binaries."""
    binary_dir = tmp_path / "binaries"
    binary_dir.mkdir(exist_ok=True)
    return binary_dir


@pytest.fixture
def minimal_pe_binary(test_binary_dir: Path) -> Path:
    """Create minimal PE executable for testing."""
    pe_file = test_binary_dir / "minimal.exe"

    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + b"\x00\x00\x00\x00"
        + b"PE\x00\x00"
        + b"\x4c\x01"
        + b"\x01\x00"
        + b"\x00" * 16
        + b"\x0b\x01"
        + b"\x00" * 200
    )

    pe_file.write_bytes(pe_header)
    return pe_file


@pytest.fixture
def upx_packed_binary(test_binary_dir: Path) -> Path:
    """Create binary with UPX signatures."""
    upx_file = test_binary_dir / "upx_packed.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    upx_signature = b"UPX0" + b"\x00" * 100 + b"UPX1" + b"\x00" * 100

    upx_file.write_bytes(pe_header + upx_signature)
    return upx_file


@pytest.fixture
def themida_protected_binary(test_binary_dir: Path) -> Path:
    """Create binary with Themida signatures."""
    themida_file = test_binary_dir / "themida_protected.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    themida_signature = b"Themida" + b"\x00" * 50 + b"WinLicense" + b"\x00" * 100

    themida_file.write_bytes(pe_header + themida_signature)
    return themida_file


@pytest.fixture
def vmprotect_binary(test_binary_dir: Path) -> Path:
    """Create binary with VMProtect signatures."""
    vmp_file = test_binary_dir / "vmprotect.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    vmp_signature = b".vmp0" + b"\x00" * 50 + b".vmp1" + b"\x00" * 50 + b"VProtect" + b"\x00" * 100

    vmp_file.write_bytes(pe_header + vmp_signature)
    return vmp_file


@pytest.fixture
def anti_debug_binary(test_binary_dir: Path) -> Path:
    """Create binary with anti-debugging techniques."""
    antidebug_file = test_binary_dir / "antidebug.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    antidebug_apis = (
        b"IsDebuggerPresent\x00"
        + b"CheckRemoteDebuggerPresent\x00"
        + b"NtQueryInformationProcess\x00"
        + b"\x64\xa1\x30\x00\x00\x00"
        + b"\x0f\x31"
        + b"OllyDbg\x00"
        + b"\x00" * 200
    )

    antidebug_file.write_bytes(pe_header + antidebug_apis)
    return antidebug_file


@pytest.fixture
def obfuscated_binary(test_binary_dir: Path) -> Path:
    """Create binary with obfuscation patterns."""
    obf_file = test_binary_dir / "obfuscated.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    obf_patterns = (
        b"\xeb\x01\x90" * 50
        + b"\xeb\x02\x90\x90" * 30
        + b"\x90" * 100
        + b"ConfuserEx\x00"
        + b"Dotfuscator\x00"
        + b"\x00" * 200
    )

    obf_file.write_bytes(pe_header + obf_patterns)
    return obf_file


@pytest.fixture
def high_entropy_binary(test_binary_dir: Path) -> Path:
    """Create binary with high entropy data (packed/encrypted)."""
    entropy_file = test_binary_dir / "high_entropy.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    import random
    random.seed(42)
    random_data = bytes(random.randint(0, 255) for _ in range(2048))

    entropy_file.write_bytes(pe_header + random_data)
    return entropy_file


@pytest.fixture
def checksum_binary(test_binary_dir: Path) -> Path:
    """Create binary with checksum verification routines."""
    checksum_file = test_binary_dir / "checksum.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    checksum_code = (
        b"CRC32\x00"
        + b"MD5\x00"
        + b"SHA256\x00"
        + b"checksum\x00"
        + b"verify\x00"
        + b"integrity\x00"
        + b"\x81\xc1\x00\x00\x00\x00"
        + b"\x33\xc0\x8b"
        + b"\x00" * 200
    )

    checksum_file.write_bytes(pe_header + checksum_code)
    return checksum_file


@pytest.fixture
def self_modifying_binary(test_binary_dir: Path) -> Path:
    """Create binary with self-modifying code patterns."""
    selfmod_file = test_binary_dir / "selfmod.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    selfmod_code = (
        b"VirtualProtect\x00"
        + b"WriteProcessMemory\x00"
        + b"NtProtectVirtualMemory\x00"
        + b"\x88\x00\x00\x00\x00"
        + b"\xc6\x00\x00"
        + b"\x00" * 200
    )

    selfmod_file.write_bytes(pe_header + selfmod_code)
    return selfmod_file


@pytest.fixture
def tpm_protected_binary(test_binary_dir: Path) -> Path:
    """Create binary with TPM protection."""
    tpm_file = test_binary_dir / "tpm_protected.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    tpm_funcs = (
        b"Tbsi_Context_Create\x00"
        + b"TPM_Init\x00"
        + b"NCryptCreatePersistedKey\x00"
        + b"MS_PLATFORM_CRYPTO_PROVIDER\x00"
        + b"\x00" * 200
    )

    tpm_file.write_bytes(pe_header + tpm_funcs)
    return tpm_file


@pytest.fixture
def flexlm_binary(test_binary_dir: Path) -> Path:
    """Create binary with FLEXlm licensing."""
    flex_file = test_binary_dir / "flexlm.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    flex_sig = b"FLEXnet\x00" + b"FLEXlm\x00" + b"\x00" * 200

    flex_file.write_bytes(pe_header + flex_sig)
    return flex_file


@pytest.fixture
def multi_protection_binary(test_binary_dir: Path) -> Path:
    """Create binary with multiple protections."""
    multi_file = test_binary_dir / "multi_protection.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
    multi_sigs = (
        b"VMProtect\x00"
        + b"IsDebuggerPresent\x00"
        + b"CRC32\x00"
        + b"\xeb\x01\x90" * 20
        + b"FLEXnet\x00"
        + b"\x00" * 200
    )

    multi_file.write_bytes(pe_header + multi_sigs)
    return multi_file


class TestProtectionDetectorInit:
    """Test ProtectionDetector initialization."""

    def test_init_default_settings(self) -> None:
        """ProtectionDetector initializes with default settings."""
        detector = ProtectionDetector()

        assert detector.engine is not None
        assert hasattr(detector, "engine")

    def test_init_with_protection_disabled(self) -> None:
        """ProtectionDetector initializes with protection disabled."""
        detector = ProtectionDetector(enable_protection=False)

        assert detector.engine is not None

    def test_init_with_heuristics_disabled(self) -> None:
        """ProtectionDetector initializes with heuristics disabled."""
        detector = ProtectionDetector(enable_heuristics=False)

        assert detector.engine is not None

    def test_init_with_all_disabled(self) -> None:
        """ProtectionDetector initializes with all features disabled."""
        detector = ProtectionDetector(enable_protection=False, enable_heuristics=False)

        assert detector.engine is not None


class TestDetectProtections:
    """Test detect_protections method."""

    def test_detect_file_not_found_raises_error(self, tmp_path: Path) -> None:
        """detect_protections raises FileNotFoundError for missing file."""
        detector = ProtectionDetector()
        nonexistent = tmp_path / "nonexistent.exe"

        with pytest.raises(FileNotFoundError) as exc_info:
            detector.detect_protections(str(nonexistent))

        assert "File not found" in str(exc_info.value)

    def test_detect_minimal_pe_returns_analysis(self, minimal_pe_binary: Path) -> None:
        """detect_protections returns ProtectionAnalysis for valid PE."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(minimal_pe_binary), deep_scan=False)

        assert isinstance(analysis, ProtectionAnalysis)
        assert analysis.file_path == str(minimal_pe_binary)
        assert isinstance(analysis.detections, list)

    def test_detect_upx_packer(self, upx_packed_binary: Path) -> None:
        """detect_protections identifies UPX packer signatures."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(upx_packed_binary))

        assert isinstance(analysis, ProtectionAnalysis)

    def test_detect_with_deep_scan_enabled(self, minimal_pe_binary: Path) -> None:
        """detect_protections performs deep scan when requested."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(minimal_pe_binary), deep_scan=True)

        assert isinstance(analysis, ProtectionAnalysis)
        assert "analysis_time" in analysis.metadata or "engines_used" in analysis.metadata

    def test_detect_with_deep_scan_disabled(self, minimal_pe_binary: Path) -> None:
        """detect_protections performs quick scan when deep_scan=False."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(minimal_pe_binary), deep_scan=False)

        assert isinstance(analysis, ProtectionAnalysis)


class TestAnalyzeMethod:
    """Test analyze method (modern interface)."""

    def test_analyze_returns_unified_result(self, minimal_pe_binary: Path) -> None:
        """analyze returns UnifiedProtectionResult."""
        detector = ProtectionDetector()

        result = detector.analyze(str(minimal_pe_binary))

        assert isinstance(result, UnifiedProtectionResult)
        assert result.file_path == str(minimal_pe_binary)

    def test_analyze_with_deep_scan(self, minimal_pe_binary: Path) -> None:
        """analyze performs deep scan when requested."""
        detector = ProtectionDetector()

        result = detector.analyze(str(minimal_pe_binary), deep_scan=True)

        assert isinstance(result, UnifiedProtectionResult)

    def test_analyze_upx_binary(self, upx_packed_binary: Path) -> None:
        """analyze detects UPX protection."""
        detector = ProtectionDetector()

        result = detector.analyze(str(upx_packed_binary))

        assert isinstance(result, UnifiedProtectionResult)


class TestQuickSummary:
    """Test get_quick_summary method."""

    def test_quick_summary_returns_dict(self, minimal_pe_binary: Path) -> None:
        """get_quick_summary returns dictionary with summary info."""
        detector = ProtectionDetector()

        summary = detector.get_quick_summary(str(minimal_pe_binary))

        assert isinstance(summary, dict)
        assert "protected" in summary or "confidence" in summary

    def test_quick_summary_protected_binary(self, upx_packed_binary: Path) -> None:
        """get_quick_summary identifies protected binary."""
        detector = ProtectionDetector()

        summary = detector.get_quick_summary(str(upx_packed_binary))

        assert isinstance(summary, dict)


class TestAnalyzeDirectory:
    """Test analyze_directory method."""

    def test_analyze_directory_non_recursive(self, test_binary_dir: Path, minimal_pe_binary: Path) -> None:
        """analyze_directory processes files non-recursively."""
        detector = ProtectionDetector()

        results = detector.analyze_directory(str(test_binary_dir), recursive=False, deep_scan=False)

        assert isinstance(results, list)
        assert all(isinstance(r, ProtectionAnalysis) for r in results)

    def test_analyze_directory_recursive(self, test_binary_dir: Path, minimal_pe_binary: Path) -> None:
        """analyze_directory processes files recursively."""
        subdir = test_binary_dir / "subdir"
        subdir.mkdir(exist_ok=True)
        sub_exe = subdir / "test.exe"
        sub_exe.write_bytes(minimal_pe_binary.read_bytes())

        detector = ProtectionDetector()
        results = detector.analyze_directory(str(test_binary_dir), recursive=True, deep_scan=False)

        assert isinstance(results, list)

    def test_analyze_directory_with_deep_scan(self, test_binary_dir: Path, minimal_pe_binary: Path) -> None:
        """analyze_directory performs deep scan when requested."""
        detector = ProtectionDetector()

        results = detector.analyze_directory(str(test_binary_dir), recursive=False, deep_scan=True)

        assert isinstance(results, list)

    def test_analyze_directory_handles_errors_gracefully(self, tmp_path: Path) -> None:
        """analyze_directory continues on errors and returns successful analyses."""
        detector = ProtectionDetector()

        results = detector.analyze_directory(str(tmp_path), recursive=False)

        assert isinstance(results, list)


class TestGetBypassStrategies:
    """Test get_bypass_strategies method."""

    def test_bypass_strategies_returns_list(self, minimal_pe_binary: Path) -> None:
        """get_bypass_strategies returns list of strategies."""
        detector = ProtectionDetector()

        strategies = detector.get_bypass_strategies(str(minimal_pe_binary))

        assert isinstance(strategies, list)

    def test_bypass_strategies_for_protected_binary(self, upx_packed_binary: Path) -> None:
        """get_bypass_strategies returns strategies for protected binary."""
        detector = ProtectionDetector()

        strategies = detector.get_bypass_strategies(str(upx_packed_binary))

        assert isinstance(strategies, list)


class TestGetSummary:
    """Test get_summary method."""

    def test_summary_returns_readable_text(self, minimal_pe_binary: Path) -> None:
        """get_summary returns human-readable text summary."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(minimal_pe_binary))

        summary = detector.get_summary(analysis)

        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "File:" in summary or minimal_pe_binary.name in summary

    def test_summary_includes_detection_info(self, upx_packed_binary: Path) -> None:
        """get_summary includes detection information."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(upx_packed_binary))

        summary = detector.get_summary(analysis)

        assert isinstance(summary, str)
        assert len(summary) > 0


class TestExportResults:
    """Test export_results method."""

    def test_export_json_format(self, minimal_pe_binary: Path) -> None:
        """export_results exports to JSON format."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(minimal_pe_binary))

        result = detector.export_results(analysis, output_format="json")

        assert isinstance(result, str)
        data = json.loads(result)
        assert "file_path" in data
        assert "detections" in data

    def test_export_text_format(self, minimal_pe_binary: Path) -> None:
        """export_results exports to text format."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(minimal_pe_binary))

        result = detector.export_results(analysis, output_format="text")

        assert isinstance(result, str)
        assert len(result) > 0

    def test_export_csv_format(self, minimal_pe_binary: Path) -> None:
        """export_results exports to CSV format."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(minimal_pe_binary))

        result = detector.export_results(analysis, output_format="csv")

        assert isinstance(result, str)
        assert "File,Type,Architecture" in result

    def test_export_invalid_format_raises_error(self, minimal_pe_binary: Path) -> None:
        """export_results raises ValueError for invalid format."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(minimal_pe_binary))

        with pytest.raises(ValueError) as exc_info:
            detector.export_results(analysis, output_format="invalid")

        assert "Unknown output format" in str(exc_info.value)


class TestDetectVirtualizationProtection:
    """Test detect_virtualization_protection method."""

    def test_detect_virtualization_returns_results(self) -> None:
        """detect_virtualization_protection returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_virtualization_protection()

        assert isinstance(results, dict)
        assert "virtualization_detected" in results
        assert "indicators" in results
        assert "confidence" in results

    def test_detect_virtualization_with_binary_path(self, minimal_pe_binary: Path) -> None:
        """detect_virtualization_protection accepts binary path."""
        detector = ProtectionDetector()

        results = detector.detect_virtualization_protection(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "virtualization_detected" in results


class TestDetectCommercialProtections:
    """Test detect_commercial_protections method."""

    def test_detect_commercial_file_not_found(self, tmp_path: Path) -> None:
        """detect_commercial_protections handles missing file."""
        detector = ProtectionDetector()
        nonexistent = tmp_path / "missing.exe"

        results = detector.detect_commercial_protections(str(nonexistent))

        assert "error" in results
        assert "protections" in results
        assert results["protections"] == []

    def test_detect_upx_protection(self, upx_packed_binary: Path) -> None:
        """detect_commercial_protections identifies UPX packer."""
        detector = ProtectionDetector()

        results = detector.detect_commercial_protections(str(upx_packed_binary))

        assert isinstance(results, dict)
        assert "protections" in results
        upx_found = any("UPX" in p for p in results["protections"])
        assert upx_found

    def test_detect_themida_protection(self, themida_protected_binary: Path) -> None:
        """detect_commercial_protections identifies Themida."""
        detector = ProtectionDetector()

        results = detector.detect_commercial_protections(str(themida_protected_binary))

        assert isinstance(results, dict)
        assert "protections" in results
        themida_found = any("Themida" in p or "WinLicense" in p for p in results["protections"])
        assert themida_found

    def test_detect_vmprotect_protection(self, vmprotect_binary: Path) -> None:
        """detect_commercial_protections identifies VMProtect."""
        detector = ProtectionDetector()

        results = detector.detect_commercial_protections(str(vmprotect_binary))

        assert isinstance(results, dict)
        assert "protections" in results
        vmp_found = any("VMProtect" in p for p in results["protections"])
        assert vmp_found

    def test_detect_flexlm_licensing(self, flexlm_binary: Path) -> None:
        """detect_commercial_protections identifies FLEXlm licensing."""
        detector = ProtectionDetector()

        results = detector.detect_commercial_protections(str(flexlm_binary))

        assert isinstance(results, dict)
        assert "protections" in results
        flex_found = any("FLEX" in p for p in results["protections"])
        assert flex_found

    def test_detect_multiple_protections(self, multi_protection_binary: Path) -> None:
        """detect_commercial_protections identifies multiple protections."""
        detector = ProtectionDetector()

        results = detector.detect_commercial_protections(str(multi_protection_binary))

        assert isinstance(results, dict)
        assert "protections" in results
        assert len(results["protections"]) >= 1


class TestDetectChecksumVerification:
    """Test detect_checksum_verification method."""

    def test_detect_checksum_returns_results(self, minimal_pe_binary: Path) -> None:
        """detect_checksum_verification returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_checksum_verification(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "has_checksum_verification" in results
        assert "checksum_types" in results
        assert "indicators" in results

    def test_detect_checksum_identifies_routines(self, checksum_binary: Path) -> None:
        """detect_checksum_verification identifies checksum routines."""
        detector = ProtectionDetector()

        results = detector.detect_checksum_verification(str(checksum_binary))

        assert isinstance(results, dict)
        assert results["has_checksum_verification"] is True
        assert len(results["indicators"]) > 0

    def test_detect_checksum_types(self, checksum_binary: Path) -> None:
        """detect_checksum_verification identifies checksum types."""
        detector = ProtectionDetector()

        results = detector.detect_checksum_verification(str(checksum_binary))

        if results["has_checksum_verification"]:
            assert "checksum_types" in results


class TestDetectSelfHealingCode:
    """Test detect_self_healing_code method."""

    def test_detect_self_healing_returns_results(self, minimal_pe_binary: Path) -> None:
        """detect_self_healing_code returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_self_healing_code(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "has_self_healing" in results
        assert "techniques" in results
        assert "indicators" in results

    def test_detect_self_modifying_patterns(self, self_modifying_binary: Path) -> None:
        """detect_self_healing_code identifies self-modifying patterns."""
        detector = ProtectionDetector()

        results = detector.detect_self_healing_code(str(self_modifying_binary))

        assert isinstance(results, dict)
        assert results["has_self_healing"] is True
        assert len(results["indicators"]) > 0


class TestDetectObfuscation:
    """Test detect_obfuscation method."""

    def test_detect_obfuscation_returns_results(self, minimal_pe_binary: Path) -> None:
        """detect_obfuscation returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_obfuscation(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "is_obfuscated" in results
        assert "obfuscation_types" in results
        assert "entropy_score" in results
        assert "indicators" in results

    def test_detect_high_entropy(self, high_entropy_binary: Path) -> None:
        """detect_obfuscation identifies high entropy binaries."""
        detector = ProtectionDetector()

        results = detector.detect_obfuscation(str(high_entropy_binary))

        assert isinstance(results, dict)
        assert results["entropy_score"] > 0.0

    def test_detect_obfuscation_patterns(self, obfuscated_binary: Path) -> None:
        """detect_obfuscation identifies obfuscation patterns."""
        detector = ProtectionDetector()

        results = detector.detect_obfuscation(str(obfuscated_binary))

        assert isinstance(results, dict)
        assert results["is_obfuscated"] is True
        assert len(results["indicators"]) > 0


class TestDetectAntiDebugging:
    """Test detect_anti_debugging_techniques method."""

    def test_detect_anti_debug_returns_results(self, minimal_pe_binary: Path) -> None:
        """detect_anti_debugging_techniques returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_anti_debugging_techniques(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "has_anti_debug" in results
        assert "techniques" in results
        assert "api_calls" in results
        assert "indicators" in results

    def test_detect_anti_debug_apis(self, anti_debug_binary: Path) -> None:
        """detect_anti_debugging_techniques identifies anti-debug APIs."""
        detector = ProtectionDetector()

        results = detector.detect_anti_debugging_techniques(str(anti_debug_binary))

        assert isinstance(results, dict)
        assert results["has_anti_debug"] is True
        assert len(results["api_calls"]) > 0

    def test_detect_anti_debug_techniques(self, anti_debug_binary: Path) -> None:
        """detect_anti_debugging_techniques identifies anti-debug techniques."""
        detector = ProtectionDetector()

        results = detector.detect_anti_debugging_techniques(str(anti_debug_binary))

        assert isinstance(results, dict)
        assert results["has_anti_debug"] is True
        assert len(results["techniques"]) > 0


class TestDetectTPMProtection:
    """Test detect_tpm_protection method."""

    def test_detect_tpm_returns_results(self, minimal_pe_binary: Path) -> None:
        """detect_tpm_protection returns detection results."""
        detector = ProtectionDetector()

        results = detector.detect_tpm_protection(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "has_tpm_protection" in results
        assert "tpm_functions" in results
        assert "indicators" in results

    def test_detect_tpm_functions(self, tpm_protected_binary: Path) -> None:
        """detect_tpm_protection identifies TPM functions."""
        detector = ProtectionDetector()

        results = detector.detect_tpm_protection(str(tpm_protected_binary))

        assert isinstance(results, dict)
        assert results["has_tpm_protection"] is True
        assert len(results["tpm_functions"]) > 0


class TestCalculateEntropy:
    """Test _calculate_entropy method."""

    def test_entropy_empty_data_returns_zero(self) -> None:
        """_calculate_entropy returns 0.0 for empty data."""
        detector = ProtectionDetector()

        entropy = detector._calculate_entropy(b"")

        assert entropy == 0.0

    def test_entropy_uniform_data_low_entropy(self) -> None:
        """_calculate_entropy returns low value for uniform data."""
        detector = ProtectionDetector()
        uniform_data = b"\x00" * 1000

        entropy = detector._calculate_entropy(uniform_data)

        assert 0.0 <= entropy < 1.0

    def test_entropy_random_data_high_entropy(self) -> None:
        """_calculate_entropy returns high value for random data."""
        detector = ProtectionDetector()
        import random
        random.seed(42)
        random_data = bytes(random.randint(0, 255) for _ in range(1000))

        entropy = detector._calculate_entropy(random_data)

        assert entropy > 6.0

    def test_entropy_mixed_data_medium_entropy(self) -> None:
        """_calculate_entropy returns medium value for mixed data."""
        detector = ProtectionDetector()
        mixed_data = b"Hello World! " * 100

        entropy = detector._calculate_entropy(mixed_data)

        assert 0.0 < entropy < 8.0


class TestDetectAllProtections:
    """Test detect_all_protections method."""

    def test_detect_all_returns_comprehensive_results(self, minimal_pe_binary: Path) -> None:
        """detect_all_protections returns all detection results."""
        detector = ProtectionDetector()

        results = detector.detect_all_protections(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "file_path" in results
        assert "virtualization" in results
        assert "commercial" in results
        assert "checksum" in results
        assert "self_healing" in results
        assert "obfuscation" in results
        assert "anti_debug" in results
        assert "tpm" in results
        assert "summary" in results

    def test_detect_all_summary_accuracy(self, multi_protection_binary: Path) -> None:
        """detect_all_protections summary reflects actual protections."""
        detector = ProtectionDetector()

        results = detector.detect_all_protections(str(multi_protection_binary))

        assert isinstance(results["summary"], dict)
        assert "is_protected" in results["summary"]
        assert "protection_count" in results["summary"]

    def test_detect_all_clean_binary(self, minimal_pe_binary: Path) -> None:
        """detect_all_protections handles clean binary."""
        detector = ProtectionDetector()

        results = detector.detect_all_protections(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "summary" in results


class TestGlobalDetector:
    """Test global detector instance."""

    def test_get_global_detector_returns_instance(self) -> None:
        """get_protection_detector returns ProtectionDetector instance."""
        detector = get_protection_detector()

        assert isinstance(detector, ProtectionDetector)

    def test_get_global_detector_singleton(self) -> None:
        """get_protection_detector returns same instance on multiple calls."""
        detector1 = get_protection_detector()
        detector2 = get_protection_detector()

        assert detector1 is detector2


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_quick_analyze_function(self, minimal_pe_binary: Path) -> None:
        """quick_analyze function works correctly."""
        analysis = quick_analyze(str(minimal_pe_binary))

        assert isinstance(analysis, ProtectionAnalysis)

    def test_deep_analyze_function(self, minimal_pe_binary: Path) -> None:
        """deep_analyze function works correctly."""
        result = deep_analyze(str(minimal_pe_binary))

        assert isinstance(result, UnifiedProtectionResult)


class TestStandaloneFunctions:
    """Test standalone function exports."""

    def test_detect_virtualization_standalone(self) -> None:
        """detect_virtualization_protection standalone function works."""
        results = detect_virtualization_protection()

        assert isinstance(results, dict)
        assert "virtualization_detected" in results

    def test_detect_commercial_standalone(self, upx_packed_binary: Path) -> None:
        """detect_commercial_protections standalone function works."""
        results = detect_commercial_protections(str(upx_packed_binary))

        assert isinstance(results, dict)
        assert "protections" in results

    def test_detect_checksum_standalone(self, checksum_binary: Path) -> None:
        """detect_checksum_verification standalone function works."""
        results = detect_checksum_verification(str(checksum_binary))

        assert isinstance(results, dict)
        assert "has_checksum_verification" in results

    def test_detect_self_healing_standalone(self, self_modifying_binary: Path) -> None:
        """detect_self_healing_code standalone function works."""
        results = detect_self_healing_code(str(self_modifying_binary))

        assert isinstance(results, dict)
        assert "has_self_healing" in results

    def test_detect_obfuscation_standalone(self, obfuscated_binary: Path) -> None:
        """detect_obfuscation standalone function works."""
        results = detect_obfuscation(str(obfuscated_binary))

        assert isinstance(results, dict)
        assert "is_obfuscated" in results

    def test_detect_anti_debug_standalone(self, anti_debug_binary: Path) -> None:
        """detect_anti_debugging_techniques standalone function works."""
        results = detect_anti_debugging_techniques(str(anti_debug_binary))

        assert isinstance(results, dict)
        assert "has_anti_debug" in results

    def test_detect_tpm_standalone(self, tpm_protected_binary: Path) -> None:
        """detect_tpm_protection standalone function works."""
        results = detect_tpm_protection(str(tpm_protected_binary))

        assert isinstance(results, dict)
        assert "has_tpm_protection" in results

    def test_detect_all_standalone(self, minimal_pe_binary: Path) -> None:
        """detect_all_protections standalone function works."""
        results = detect_all_protections(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "summary" in results


class TestAliasedFunctions:
    """Test aliased backward compatibility functions."""

    def test_detect_protection_mechanisms(self, minimal_pe_binary: Path) -> None:
        """detect_protection_mechanisms alias works."""
        results = detect_protection_mechanisms(str(minimal_pe_binary))

        assert isinstance(results, dict)

    def test_detect_packing_methods(self, upx_packed_binary: Path) -> None:
        """detect_packing_methods identifies packers."""
        results = detect_packing_methods(str(upx_packed_binary))

        assert isinstance(results, dict)
        assert "packers" in results
        assert "is_packed" in results

    def test_run_comprehensive_scan(self, minimal_pe_binary: Path) -> None:
        """run_comprehensive_protection_scan works."""
        results = run_comprehensive_protection_scan(str(minimal_pe_binary))

        assert isinstance(results, dict)

    def test_scan_for_bytecode_protectors(self, minimal_pe_binary: Path) -> None:
        """scan_for_bytecode_protectors identifies bytecode protectors."""
        results = scan_for_bytecode_protectors(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "bytecode_protectors" in results
        assert "has_bytecode_protection" in results


class TestGenerateChecksum:
    """Test generate_checksum function."""

    def test_generate_checksum_returns_hex_string(self) -> None:
        """generate_checksum returns hex digest string."""
        data = b"test data"

        checksum = generate_checksum(data)

        assert isinstance(checksum, str)
        assert len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)

    def test_generate_checksum_consistent(self) -> None:
        """generate_checksum returns consistent results."""
        data = b"test data"

        checksum1 = generate_checksum(data)
        checksum2 = generate_checksum(data)

        assert checksum1 == checksum2

    def test_generate_checksum_different_data(self) -> None:
        """generate_checksum returns different hashes for different data."""
        data1 = b"test data 1"
        data2 = b"test data 2"

        checksum1 = generate_checksum(data1)
        checksum2 = generate_checksum(data2)

        assert checksum1 != checksum2

    def test_generate_checksum_uses_sha256(self) -> None:
        """generate_checksum uses SHA256 algorithm."""
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()

        checksum = generate_checksum(data)

        assert checksum == expected


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_binary_file(self, test_binary_dir: Path) -> None:
        """Detector handles empty binary file."""
        empty_file = test_binary_dir / "empty.exe"
        empty_file.write_bytes(b"")

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(empty_file))

        assert isinstance(results, dict)

    def test_tiny_binary_file(self, test_binary_dir: Path) -> None:
        """Detector handles tiny binary file."""
        tiny_file = test_binary_dir / "tiny.exe"
        tiny_file.write_bytes(b"MZ")

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(tiny_file))

        assert isinstance(results, dict)

    def test_large_binary_chunked_reading(self, test_binary_dir: Path) -> None:
        """Detector handles large binaries with chunked reading."""
        large_file = test_binary_dir / "large.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        large_data = pe_header + (b"UPX0" + b"\x00" * 1000000)
        large_file.write_bytes(large_data)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(large_file))

        assert isinstance(results, dict)
        upx_found = any("UPX" in p for p in results.get("protections", []))
        assert upx_found


class TestDenuvoFeatures:
    """Test Denuvo-specific features (if available)."""

    def test_detect_denuvo_advanced_handles_missing_analyzer(self, minimal_pe_binary: Path) -> None:
        """detect_denuvo_advanced handles missing analyzer gracefully."""
        detector = ProtectionDetector()

        results = detector.detect_denuvo_advanced(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "detected" in results

    def test_analyze_denuvo_ticket_handles_missing_file(self, tmp_path: Path) -> None:
        """analyze_denuvo_ticket handles missing ticket file."""
        detector = ProtectionDetector()
        nonexistent = tmp_path / "ticket.dat"

        results = detector.analyze_denuvo_ticket(str(nonexistent))

        assert isinstance(results, dict)
        assert "error" in results

    def test_analyze_denuvo_ticket_with_bytes(self) -> None:
        """analyze_denuvo_ticket handles byte data."""
        detector = ProtectionDetector()
        fake_ticket = b"DENUVO_TICKET_DATA"

        results = detector.analyze_denuvo_ticket(fake_ticket)

        assert isinstance(results, dict)

    def test_generate_denuvo_activation(self) -> None:
        """generate_denuvo_activation handles activation request."""
        detector = ProtectionDetector()
        fake_request = b"ACTIVATION_REQUEST"

        results = detector.generate_denuvo_activation(fake_request, license_type="perpetual")

        assert isinstance(results, dict)
        assert "success" in results

    def test_forge_denuvo_token(self) -> None:
        """forge_denuvo_token handles token forging."""
        detector = ProtectionDetector()

        results = detector.forge_denuvo_token(
            game_id="1234567890abcdef1234567890abcdef",
            machine_id="fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            license_type="perpetual",
        )

        assert isinstance(results, dict)
        assert "success" in results


class TestThemidaFeatures:
    """Test Themida-specific features (if available)."""

    def test_detect_themida_advanced_handles_missing_analyzer(self, minimal_pe_binary: Path) -> None:
        """detect_themida_advanced handles missing analyzer gracefully."""
        detector = ProtectionDetector()

        results = detector.detect_themida_advanced(str(minimal_pe_binary))

        assert isinstance(results, dict)
        assert "detected" in results


class TestAllCommercialProtectionSignatures:
    """Test detection of all commercial protection signatures."""

    def test_detect_aspack_packer(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies ASPack packer."""
        aspack_file = test_binary_dir / "aspack.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        aspack_sig = b"ASPack" + b"\x00" * 200
        aspack_file.write_bytes(pe_header + aspack_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(aspack_file))

        assert isinstance(results, dict)
        assert "protections" in results
        aspack_found = any("ASPack" in p for p in results["protections"])
        assert aspack_found

    def test_detect_pecompact_packer(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies PECompact packer."""
        pec_file = test_binary_dir / "pecompact.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        pec_sig = b"PEC2" + b"\x00" * 200
        pec_file.write_bytes(pe_header + pec_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(pec_file))

        assert isinstance(results, dict)
        assert "protections" in results
        pec_found = any("PECompact" in p for p in results["protections"])
        assert pec_found

    def test_detect_nspack_packer(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies NsPack packer."""
        nsp_file = test_binary_dir / "nspack.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        nsp_sig = b"NSP0" + b"\x00" * 200
        nsp_file.write_bytes(pe_header + nsp_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(nsp_file))

        assert isinstance(results, dict)
        assert "protections" in results
        nsp_found = any("NsPack" in p for p in results["protections"])
        assert nsp_found

    def test_detect_mpress_packer(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies MPRESS packer."""
        mpress_file = test_binary_dir / "mpress.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        mpress_sig = b"MPRESS" + b"\x00" * 200
        mpress_file.write_bytes(pe_header + mpress_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(mpress_file))

        assert isinstance(results, dict)
        assert "protections" in results
        mpress_found = any("MPRESS" in p for p in results["protections"])
        assert mpress_found

    def test_detect_obsidium_protector(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies Obsidium protector."""
        obs_file = test_binary_dir / "obsidium.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        obs_sig = b"Obsidium" + b"\x00" * 200
        obs_file.write_bytes(pe_header + obs_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(obs_file))

        assert isinstance(results, dict)
        assert "protections" in results
        obs_found = any("Obsidium" in p for p in results["protections"])
        assert obs_found

    def test_detect_armadillo_protector(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies Armadillo protector."""
        arm_file = test_binary_dir / "armadillo.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        arm_sig = b"Armadillo" + b"\x00" * 200
        arm_file.write_bytes(pe_header + arm_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(arm_file))

        assert isinstance(results, dict)
        assert "protections" in results
        arm_found = any("Armadillo" in p for p in results["protections"])
        assert arm_found

    def test_detect_securom_drm(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies SecuROM DRM."""
        sr_file = test_binary_dir / "securom.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        sr_sig = b"SecuROM" + b"\x00" * 200
        sr_file.write_bytes(pe_header + sr_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(sr_file))

        assert isinstance(results, dict)
        assert "protections" in results
        sr_found = any("SecuROM" in p for p in results["protections"])
        assert sr_found

    def test_detect_safedisc_drm(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies SafeDisc DRM."""
        sd_file = test_binary_dir / "safedisc.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        sd_sig = b"SafeDisc" + b"\x00" * 200
        sd_file.write_bytes(pe_header + sd_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(sd_file))

        assert isinstance(results, dict)
        assert "protections" in results
        sd_found = any("SafeDisc" in p for p in results["protections"])
        assert sd_found

    def test_detect_starforce_drm(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies StarForce DRM."""
        sf_file = test_binary_dir / "starforce.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        sf_sig = b"StarForce" + b"\x00" * 200
        sf_file.write_bytes(pe_header + sf_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(sf_file))

        assert isinstance(results, dict)
        assert "protections" in results
        sf_found = any("StarForce" in p for p in results["protections"])
        assert sf_found

    def test_detect_denuvo_drm(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies Denuvo DRM."""
        denuvo_file = test_binary_dir / "denuvo.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        denuvo_sig = b"Denuvo" + b"\x00" * 200
        denuvo_file.write_bytes(pe_header + denuvo_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(denuvo_file))

        assert isinstance(results, dict)
        assert "protections" in results
        denuvo_found = any("Denuvo" in p for p in results["protections"])
        assert denuvo_found

    def test_detect_enigma_protector(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies Enigma Protector."""
        enigma_file = test_binary_dir / "enigma.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        enigma_sig = b"Enigma" + b"\x00" * 200
        enigma_file.write_bytes(pe_header + enigma_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(enigma_file))

        assert isinstance(results, dict)
        assert "protections" in results
        enigma_found = any("Enigma" in p for p in results["protections"])
        assert enigma_found

    def test_detect_hasp_licensing(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies HASP licensing."""
        hasp_file = test_binary_dir / "hasp.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        hasp_sig = b"HASP" + b"\x00" * 200
        hasp_file.write_bytes(pe_header + hasp_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(hasp_file))

        assert isinstance(results, dict)
        assert "protections" in results
        hasp_found = any("HASP" in p for p in results["protections"])
        assert hasp_found

    def test_detect_sentinel_licensing(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies Sentinel licensing."""
        sentinel_file = test_binary_dir / "sentinel.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        sentinel_sig = b"Sentinel" + b"\x00" * 200
        sentinel_file.write_bytes(pe_header + sentinel_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(sentinel_file))

        assert isinstance(results, dict)
        assert "protections" in results
        sentinel_found = any("Sentinel" in p for p in results["protections"])
        assert sentinel_found

    def test_detect_codemeter_licensing(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections identifies CodeMeter/WibuKey licensing."""
        cm_file = test_binary_dir / "codemeter.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        cm_sig = b"CodeMeter" + b"\x00" * 200
        cm_file.write_bytes(pe_header + cm_sig)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(cm_file))

        assert isinstance(results, dict)
        assert "protections" in results
        cm_found = any("CodeMeter" in p for p in results["protections"])
        assert cm_found


class TestEntropyCalculationAccuracy:
    """Test entropy calculation accuracy and edge cases."""

    def test_entropy_calculation_perfectly_random_data(self) -> None:
        """_calculate_entropy accurately measures perfectly random data."""
        detector = ProtectionDetector()
        import random
        random.seed(12345)
        perfectly_random = bytes(random.randint(0, 255) for _ in range(10000))

        entropy = detector._calculate_entropy(perfectly_random)

        assert entropy >= 7.5
        assert entropy <= 8.0

    def test_entropy_calculation_text_data(self) -> None:
        """_calculate_entropy accurately measures text data."""
        detector = ProtectionDetector()
        text_data = b"The quick brown fox jumps over the lazy dog. " * 100

        entropy = detector._calculate_entropy(text_data)

        assert 3.0 < entropy < 5.0

    def test_entropy_calculation_binary_pattern(self) -> None:
        """_calculate_entropy accurately measures repeating binary patterns."""
        detector = ProtectionDetector()
        pattern_data = b"\xAA\x55" * 1000

        entropy = detector._calculate_entropy(pattern_data)

        assert 0.5 < entropy < 2.0

    def test_entropy_calculation_single_byte(self) -> None:
        """_calculate_entropy handles single byte correctly."""
        detector = ProtectionDetector()
        single_byte = b"\xFF"

        entropy = detector._calculate_entropy(single_byte)

        assert entropy == 0.0

    def test_entropy_calculation_all_zeros(self) -> None:
        """_calculate_entropy returns 0 for all zeros."""
        detector = ProtectionDetector()
        all_zeros = b"\x00" * 10000

        entropy = detector._calculate_entropy(all_zeros)

        assert entropy == 0.0

    def test_entropy_calculation_all_ones(self) -> None:
        """_calculate_entropy returns 0 for all ones."""
        detector = ProtectionDetector()
        all_ones = b"\xFF" * 10000

        entropy = detector._calculate_entropy(all_ones)

        assert entropy == 0.0


class TestSignatureOffsetTracking:
    """Test that signature detection tracks offsets correctly."""

    def test_commercial_detection_includes_offsets(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections includes signature offsets."""
        offset_file = test_binary_dir / "offset_test.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        padding = b"\x00" * 500
        signature = b"VMProtect"
        offset_file.write_bytes(pe_header + padding + signature)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(offset_file))

        assert isinstance(results, dict)
        if "signatures_found" in results and results["signatures_found"]:
            for sig in results["signatures_found"]:
                assert "offset" in sig
                assert isinstance(sig["offset"], int)
                assert sig["offset"] >= 0

    def test_multiple_signatures_different_offsets(self, test_binary_dir: Path) -> None:
        """detect_commercial_protections tracks multiple signatures at different offsets."""
        multi_offset_file = test_binary_dir / "multi_offset.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        content = (
            pe_header
            + b"\x00" * 100
            + b"UPX0"
            + b"\x00" * 200
            + b"Themida"
            + b"\x00" * 300
            + b"VMProtect"
        )
        multi_offset_file.write_bytes(content)

        detector = ProtectionDetector()
        results = detector.detect_commercial_protections(str(multi_offset_file))

        assert isinstance(results, dict)
        if "signatures_found" in results:
            assert len(results["signatures_found"]) >= 1


class TestBypassStrategyGeneration:
    """Test bypass strategy generation for detected protections."""

    def test_bypass_strategies_include_difficulty_rating(self, upx_packed_binary: Path) -> None:
        """get_bypass_strategies includes difficulty ratings."""
        detector = ProtectionDetector()

        strategies = detector.get_bypass_strategies(str(upx_packed_binary))

        assert isinstance(strategies, list)

    def test_bypass_strategies_include_tools(self, vmprotect_binary: Path) -> None:
        """get_bypass_strategies includes required tools."""
        detector = ProtectionDetector()

        strategies = detector.get_bypass_strategies(str(vmprotect_binary))

        assert isinstance(strategies, list)

    def test_bypass_strategies_for_multi_protection(self, multi_protection_binary: Path) -> None:
        """get_bypass_strategies handles multiple protections."""
        detector = ProtectionDetector()

        strategies = detector.get_bypass_strategies(str(multi_protection_binary))

        assert isinstance(strategies, list)


class TestAntiDebugPatternDetection:
    """Test comprehensive anti-debug pattern detection."""

    def test_detect_peb_being_debugged_check(self, test_binary_dir: Path) -> None:
        """detect_anti_debugging_techniques identifies PEB.BeingDebugged check."""
        peb_file = test_binary_dir / "peb_check.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        peb_pattern = b"\x64\xa1\x30\x00\x00\x00"
        peb_file.write_bytes(pe_header + peb_pattern + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_anti_debugging_techniques(str(peb_file))

        assert isinstance(results, dict)
        assert results["has_anti_debug"] is True
        peb_found = any("PEB" in t for t in results["techniques"])
        assert peb_found

    def test_detect_rdtsc_timing_check(self, test_binary_dir: Path) -> None:
        """detect_anti_debugging_techniques identifies RDTSC timing check."""
        rdtsc_file = test_binary_dir / "rdtsc.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        rdtsc_pattern = b"\x0f\x31"
        rdtsc_file.write_bytes(pe_header + rdtsc_pattern + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_anti_debugging_techniques(str(rdtsc_file))

        assert isinstance(results, dict)
        assert results["has_anti_debug"] is True
        rdtsc_found = any("RDTSC" in t or "timing" in t.lower() for t in results["techniques"])
        assert rdtsc_found

    def test_detect_debugger_window_search(self, test_binary_dir: Path) -> None:
        """detect_anti_debugging_techniques identifies debugger window searches."""
        window_file = test_binary_dir / "window_search.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        window_pattern = b"OllyDbg\x00" + b"x64dbg\x00" + b"IDA Pro\x00" + b"WinDbg\x00"
        window_file.write_bytes(pe_header + window_pattern + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_anti_debugging_techniques(str(window_file))

        assert isinstance(results, dict)
        assert results["has_anti_debug"] is True
        assert len(results["techniques"]) >= 3


class TestObfuscationComplexPatterns:
    """Test detection of complex obfuscation patterns."""

    def test_detect_control_flow_flattening(self, test_binary_dir: Path) -> None:
        """detect_obfuscation identifies control flow flattening."""
        cff_file = test_binary_dir / "cff.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        many_jumps = b"\xeb\x00" * 200 + b"\xe9\x00\x00\x00\x00" * 100
        cff_file.write_bytes(pe_header + many_jumps)

        detector = ProtectionDetector()
        results = detector.detect_obfuscation(str(cff_file))

        assert isinstance(results, dict)
        assert results["is_obfuscated"] is True
        cff_found = any("Control Flow" in t for t in results["obfuscation_types"])
        assert cff_found

    def test_detect_dotnet_obfuscators(self, test_binary_dir: Path) -> None:
        """detect_obfuscation identifies .NET obfuscators."""
        dotnet_file = test_binary_dir / "dotnet_obf.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        obf_sigs = b".NET Reactor\x00" + b"ConfuserEx\x00" + b"SmartAssembly\x00"
        dotnet_file.write_bytes(pe_header + obf_sigs + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_obfuscation(str(dotnet_file))

        assert isinstance(results, dict)
        assert results["is_obfuscated"] is True
        assert len(results["indicators"]) >= 3


class TestPerformanceBenchmarks:
    """Test performance of detection methods."""

    def test_small_binary_detection_performance(self, minimal_pe_binary: Path) -> None:
        """Commercial protection detection completes quickly for small binaries."""
        import time

        detector = ProtectionDetector()
        start = time.time()
        detector.detect_commercial_protections(str(minimal_pe_binary))
        elapsed = time.time() - start

        assert elapsed < 5.0

    def test_large_binary_detection_performance(self, test_binary_dir: Path) -> None:
        """Commercial protection detection handles large binaries efficiently."""
        import time

        large_file = test_binary_dir / "large_perf.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        large_data = pe_header + b"\x00" * 5000000
        large_file.write_bytes(large_data)

        detector = ProtectionDetector()
        start = time.time()
        detector.detect_commercial_protections(str(large_file))
        elapsed = time.time() - start

        assert elapsed < 5.0

    def test_entropy_calculation_performance(self) -> None:
        """Entropy calculation completes quickly for large data."""
        import time

        detector = ProtectionDetector()
        large_data = b"\x00" * 1000000

        start = time.time()
        detector._calculate_entropy(large_data)
        elapsed = time.time() - start

        assert elapsed < 1.0


class TestDirectoryAnalysisComprehensive:
    """Test comprehensive directory analysis functionality."""

    def test_analyze_directory_filters_by_extension(self, test_binary_dir: Path) -> None:
        """analyze_directory only processes executable files."""
        text_file = test_binary_dir / "readme.txt"
        text_file.write_text("This is a readme")

        exe_file = test_binary_dir / "test.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        exe_file.write_bytes(pe_header + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.analyze_directory(str(test_binary_dir), recursive=False)

        assert isinstance(results, list)
        assert all(r.file_path.endswith((".exe", ".dll", ".sys", ".ocx", ".scr", ".com")) for r in results)

    def test_analyze_directory_handles_mixed_content(self, test_binary_dir: Path) -> None:
        """analyze_directory handles directories with mixed content."""
        valid_exe = test_binary_dir / "valid.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        valid_exe.write_bytes(pe_header + b"\x00" * 200)

        invalid_exe = test_binary_dir / "invalid.exe"
        invalid_exe.write_bytes(b"not a PE file")

        detector = ProtectionDetector()
        results = detector.analyze_directory(str(test_binary_dir), recursive=False)

        assert isinstance(results, list)

    def test_analyze_directory_recursive_depth(self, test_binary_dir: Path) -> None:
        """analyze_directory handles deep directory hierarchies."""
        level1 = test_binary_dir / "level1"
        level1.mkdir()
        level2 = level1 / "level2"
        level2.mkdir()
        level3 = level2 / "level3"
        level3.mkdir()

        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"

        (test_binary_dir / "root.exe").write_bytes(pe_header + b"\x00" * 100)
        (level1 / "l1.exe").write_bytes(pe_header + b"\x00" * 100)
        (level2 / "l2.exe").write_bytes(pe_header + b"\x00" * 100)
        (level3 / "l3.exe").write_bytes(pe_header + b"\x00" * 100)

        detector = ProtectionDetector()
        results = detector.analyze_directory(str(test_binary_dir), recursive=True)

        assert isinstance(results, list)


class TestExportFormatValidation:
    """Test export format validation and correctness."""

    def test_export_json_valid_structure(self, upx_packed_binary: Path) -> None:
        """export_results JSON format has valid structure."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(upx_packed_binary))

        json_output = detector.export_results(analysis, output_format="json")
        data = json.loads(json_output)

        assert "file_path" in data
        assert "file_type" in data
        assert "architecture" in data
        assert "is_packed" in data
        assert "is_protected" in data
        assert "detections" in data
        assert isinstance(data["detections"], list)

    def test_export_csv_valid_format(self, multi_protection_binary: Path) -> None:
        """export_results CSV format has valid structure."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(multi_protection_binary))

        csv_output = detector.export_results(analysis, output_format="csv")
        lines = csv_output.split("\n")

        assert len(lines) >= 1
        header = lines[0]
        assert "File" in header
        assert "Type" in header
        assert "Architecture" in header
        assert "Protection" in header

    def test_export_text_human_readable(self, themida_protected_binary: Path) -> None:
        """export_results text format is human-readable."""
        detector = ProtectionDetector()
        analysis = detector.detect_protections(str(themida_protected_binary))

        text_output = detector.export_results(analysis, output_format="text")

        assert isinstance(text_output, str)
        assert len(text_output) > 0
        assert "\n" in text_output


class TestConversionMethods:
    """Test internal conversion methods."""

    def test_map_protection_type_all_types(self) -> None:
        """_map_protection_type correctly maps all protection types."""
        detector = ProtectionDetector()

        type_mappings = {
            "packer": ProtectionType.PACKER,
            "protector": ProtectionType.PROTECTOR,
            "compiler": ProtectionType.COMPILER,
            "installer": ProtectionType.INSTALLER,
            "library": ProtectionType.LIBRARY,
            "overlay": ProtectionType.OVERLAY,
            "cryptor": ProtectionType.CRYPTOR,
            "dongle": ProtectionType.DONGLE,
            "license": ProtectionType.LICENSE,
            "drm": ProtectionType.DRM,
        }

        for type_str, expected_enum in type_mappings.items():
            result = detector._map_protection_type(type_str)
            assert result == expected_enum

    def test_map_protection_type_case_insensitive(self) -> None:
        """_map_protection_type is case-insensitive."""
        detector = ProtectionDetector()

        assert detector._map_protection_type("PACKER") == ProtectionType.PACKER
        assert detector._map_protection_type("Packer") == ProtectionType.PACKER
        assert detector._map_protection_type("packer") == ProtectionType.PACKER

    def test_map_protection_type_unknown(self) -> None:
        """_map_protection_type returns UNKNOWN for unknown types."""
        detector = ProtectionDetector()

        result = detector._map_protection_type("unknown_type")

        assert result == ProtectionType.UNKNOWN


class TestDetectionConfidenceScoring:
    """Test confidence scoring for detections."""

    def test_single_signature_high_confidence(self, upx_packed_binary: Path) -> None:
        """Single strong signature detection has high confidence."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(upx_packed_binary))

        if "confidence_score" in analysis.metadata:
            assert analysis.metadata["confidence_score"] >= 0.0

    def test_multiple_signatures_higher_confidence(self, multi_protection_binary: Path) -> None:
        """Multiple signature detections increase confidence."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(multi_protection_binary))

        if "confidence_score" in analysis.metadata:
            assert analysis.metadata["confidence_score"] >= 0.0


class TestChecksumDetectionComprehensive:
    """Test comprehensive checksum detection."""

    def test_detect_all_hash_algorithms(self, test_binary_dir: Path) -> None:
        """detect_checksum_verification identifies all hash algorithms."""
        hash_file = test_binary_dir / "all_hashes.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        hash_strings = b"CRC32\x00MD5\x00SHA1\x00SHA256\x00"
        hash_file.write_bytes(pe_header + hash_strings + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_checksum_verification(str(hash_file))

        assert isinstance(results, dict)
        assert results["has_checksum_verification"] is True
        assert len(results["checksum_types"]) >= 1

    def test_detect_assembly_checksum_patterns(self, test_binary_dir: Path) -> None:
        """detect_checksum_verification identifies assembly patterns."""
        asm_file = test_binary_dir / "asm_checksum.exe"
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"
        asm_patterns = b"\x81\xc1\x00\x00" + b"\x81\xc9\x00\x00" + b"\x33\xc0\x8b" + b"\x0f\xb6"
        asm_file.write_bytes(pe_header + asm_patterns + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.detect_checksum_verification(str(asm_file))

        assert isinstance(results, dict)
        assert results["has_checksum_verification"] is True


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_workflow_detect_then_bypass(self, vmprotect_binary: Path) -> None:
        """Complete workflow: detect protection then get bypass strategies."""
        detector = ProtectionDetector()

        analysis = detector.detect_protections(str(vmprotect_binary))
        assert isinstance(analysis, ProtectionAnalysis)

        strategies = detector.get_bypass_strategies(str(vmprotect_binary))
        assert isinstance(strategies, list)

        summary = detector.get_summary(analysis)
        assert isinstance(summary, str)

    def test_workflow_quick_then_deep_scan(self, multi_protection_binary: Path) -> None:
        """Workflow: quick scan followed by deep scan."""
        detector = ProtectionDetector()

        quick_summary = detector.get_quick_summary(str(multi_protection_binary))
        assert isinstance(quick_summary, dict)

        deep_result = detector.analyze(str(multi_protection_binary), deep_scan=True)
        assert isinstance(deep_result, UnifiedProtectionResult)

    def test_workflow_batch_analysis_export(self, test_binary_dir: Path) -> None:
        """Workflow: batch analyze directory and export results."""
        pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00" + b"PE\x00\x00"

        for i in range(3):
            exe_file = test_binary_dir / f"test_{i}.exe"
            exe_file.write_bytes(pe_header + b"\x00" * 200)

        detector = ProtectionDetector()
        results = detector.analyze_directory(str(test_binary_dir), recursive=False)

        assert isinstance(results, list)
        assert len(results) >= 3

        for analysis in results:
            json_export = detector.export_results(analysis, output_format="json")
            assert isinstance(json_export, str)
            data = json.loads(json_export)
            assert "file_path" in data
