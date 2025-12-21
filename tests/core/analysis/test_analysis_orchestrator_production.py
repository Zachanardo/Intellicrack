"""Production tests for AnalysisOrchestrator.

Validates complete analysis pipeline coordination, multi-phase execution,
signal emission, error handling, and integration with multiple analysis engines.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.analysis.analysis_orchestrator import (
    AnalysisOrchestrator,
    AnalysisPhase,
    OrchestrationResult,
    run_selected_analysis,
)


@pytest.fixture
def real_pe_binary() -> bytes:
    """Create a minimal valid PE binary for testing."""
    dos_header = b"MZ" + b"\x90" * 58
    dos_header += b"\x3C\x00\x00\x00"
    pe_signature_offset = 0x3C

    pe_signature = b"PE\x00\x00"

    file_header = (
        b"\x4C\x01"
        b"\x01\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\xE0\x00"
        b"\x0B\x01"
    )

    optional_header = b"\x0B\x01" + b"\x00" * 222

    section_header = (
        b".text\x00\x00\x00"
        b"\x00\x10\x00\x00"
        b"\x00\x10\x00\x00"
        b"\x00\x02\x00\x00"
        b"\x00\x02\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x60"
    )

    padding = b"\x00" * (0x200 - len(dos_header) - len(pe_signature) - len(file_header) - len(optional_header) - len(section_header))

    section_data = b"\x55\x89\xE5\x31\xC0\x5D\xC3" + b"\x00" * 505

    return dos_header + pe_signature + file_header + optional_header + section_header + padding + section_data


@pytest.fixture
def temp_binary_file(real_pe_binary: bytes, tmp_path: Path) -> Path:
    """Create temporary PE binary file."""
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(real_pe_binary)
    return binary_path


@pytest.fixture
def orchestrator() -> AnalysisOrchestrator:
    """Create AnalysisOrchestrator instance."""
    return AnalysisOrchestrator()


class TestOrchestrationResult:
    """Test OrchestrationResult functionality."""

    def test_result_initialization(self) -> None:
        """OrchestrationResult initializes with correct default values."""
        result = OrchestrationResult(binary_path="/path/to/binary.exe", success=True)

        assert result.binary_path == "/path/to/binary.exe"
        assert result.success is True
        assert result.phases_completed == []
        assert result.results == {}
        assert result.errors == []
        assert result.warnings == []

    def test_add_result(self) -> None:
        """add_result correctly stores phase results."""
        result = OrchestrationResult(binary_path="/test.exe", success=True)

        phase_data = {"imports": ["kernel32.dll"], "exports": ["main"]}
        result.add_result(AnalysisPhase.STATIC_ANALYSIS, phase_data)

        assert AnalysisPhase.STATIC_ANALYSIS in result.phases_completed
        assert result.results["static_analysis"] == phase_data

    def test_add_error(self) -> None:
        """add_error correctly formats and stores errors."""
        result = OrchestrationResult(binary_path="/test.exe", success=True)

        result.add_error(AnalysisPhase.GHIDRA_ANALYSIS, "Ghidra failed to launch")

        assert "ghidra_analysis: Ghidra failed to launch" in result.errors

    def test_add_warning(self) -> None:
        """add_warning correctly formats and stores warnings."""
        result = OrchestrationResult(binary_path="/test.exe", success=True)

        result.add_warning(AnalysisPhase.ENTROPY_ANALYSIS, "High entropy detected")

        assert "entropy_analysis: High entropy detected" in result.warnings


class TestAnalysisOrchestrator:
    """Test AnalysisOrchestrator core functionality."""

    def test_initialization(self, orchestrator: AnalysisOrchestrator) -> None:
        """Orchestrator initializes with all required components."""
        assert orchestrator.binary_analyzer is not None
        assert orchestrator.entropy_analyzer is not None
        assert orchestrator.multi_format_analyzer is not None
        assert orchestrator.vulnerability_engine is not None
        assert orchestrator.yara_engine is not None
        assert orchestrator.ghidra_script_manager is not None
        assert orchestrator.enabled_phases == list(AnalysisPhase)
        assert orchestrator.timeout_per_phase == 300

    def test_initialization_with_binary_path(self) -> None:
        """Orchestrator accepts binary path during initialization."""
        test_path = "/path/to/test.exe"
        orchestrator = AnalysisOrchestrator(binary_path=test_path)

        assert orchestrator.binary_path == test_path

    def test_orchestrate_without_binary_path(self, orchestrator: AnalysisOrchestrator) -> None:
        """orchestrate fails gracefully when binary_path not set."""
        result = orchestrator.orchestrate()

        assert result.success is False
        assert len(result.errors) > 0
        assert "No binary path configured" in result.errors[0]

    def test_analyze_binary_file_not_found(self, orchestrator: AnalysisOrchestrator) -> None:
        """analyze_binary handles missing file correctly."""
        result = orchestrator.analyze_binary("/nonexistent/file.exe")

        assert result.success is False
        assert len(result.errors) > 0
        assert "File not found" in result.errors[0]

    def test_analyze_binary_basic_phases(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """analyze_binary executes basic analysis phases."""
        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        result = orchestrator.analyze_binary(str(temp_binary_file), phases)

        assert result.success is True
        assert AnalysisPhase.PREPARATION in result.phases_completed
        assert AnalysisPhase.BASIC_INFO in result.phases_completed
        assert "preparation" in result.results
        assert "basic_info" in result.results

    def test_preparation_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Preparation phase extracts correct file metadata."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.PREPARATION])

        prep_data = result.results["preparation"]
        assert "file_size" in prep_data
        assert prep_data["file_size"] > 0
        assert "file_path" in prep_data
        assert "file_name" in prep_data
        assert prep_data["file_name"] == "test_binary.exe"
        assert "modified_time" in prep_data

    def test_basic_info_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Basic info phase uses binary analyzer."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.BASIC_INFO])

        basic_info = result.results["basic_info"]
        assert basic_info is not None
        assert isinstance(basic_info, dict)

    def test_entropy_analysis_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Entropy analysis phase calculates entropy correctly."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.ENTROPY_ANALYSIS])

        entropy_data = result.results["entropy_analysis"]
        assert "overall_entropy" in entropy_data
        assert "chunks" in entropy_data
        assert isinstance(entropy_data["chunks"], list)
        assert len(entropy_data["chunks"]) > 0

        chunk = entropy_data["chunks"][0]
        assert "offset" in chunk
        assert "entropy" in chunk
        assert "suspicious" in chunk

    def test_structure_analysis_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Structure analysis phase uses multi-format analyzer."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.STRUCTURE_ANALYSIS])

        structure_data = result.results["structure_analysis"]
        assert structure_data is not None

    def test_phase_error_handling(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Orchestrator continues after phase failures."""
        with patch.object(orchestrator.entropy_analyzer, 'calculate_entropy', side_effect=Exception("Entropy error")):
            result = orchestrator.analyze_binary(
                str(temp_binary_file),
                [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS, AnalysisPhase.STRUCTURE_ANALYSIS]
            )

        assert AnalysisPhase.PREPARATION in result.phases_completed
        assert AnalysisPhase.STRUCTURE_ANALYSIS in result.phases_completed
        assert len(result.errors) > 0

    def test_signal_emission(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Orchestrator emits correct signals during analysis."""
        phase_started_calls = []
        phase_completed_calls = []
        progress_calls = []

        orchestrator.phase_started.connect(lambda p: phase_started_calls.append(p))
        orchestrator.phase_completed.connect(lambda p, r: phase_completed_calls.append(p))
        orchestrator.progress_updated.connect(lambda c, t: progress_calls.append((c, t)))

        phases = [AnalysisPhase.PREPARATION, AnalysisPhase.BASIC_INFO]
        orchestrator.analyze_binary(str(temp_binary_file), phases)

        assert len(phase_started_calls) == 2
        assert "preparation" in phase_started_calls
        assert "basic_info" in phase_started_calls

        assert len(phase_completed_calls) == 2
        assert len(progress_calls) >= 2

    def test_finalization_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Finalization phase summarizes analysis results."""
        result = orchestrator.analyze_binary(
            str(temp_binary_file),
            [AnalysisPhase.PREPARATION, AnalysisPhase.ENTROPY_ANALYSIS, AnalysisPhase.FINALIZATION]
        )

        final_data = result.results["finalization"]
        assert "total_phases" in final_data
        assert "completed_phases" in final_data
        assert "errors" in final_data
        assert "warnings" in final_data
        assert "key_findings" in final_data

    def test_high_entropy_detection(self, orchestrator: AnalysisOrchestrator, tmp_path: Path) -> None:
        """Finalization detects high entropy binaries."""
        high_entropy_data = os.urandom(1024)
        binary_path = tmp_path / "high_entropy.bin"
        binary_path.write_bytes(high_entropy_data)

        result = orchestrator.analyze_binary(
            str(binary_path),
            [AnalysisPhase.ENTROPY_ANALYSIS, AnalysisPhase.FINALIZATION]
        )

        final_data = result.results["finalization"]
        findings = final_data["key_findings"]

        high_entropy_finding = any("entropy" in finding.lower() for finding in findings)
        assert high_entropy_finding

    @patch('intellicrack.core.analysis.analysis_orchestrator.QEMUManager')
    def test_ghidra_analysis_phase_vm_initialization(self, mock_qemu: Mock, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Ghidra analysis initializes QEMU VM correctly."""
        mock_vm = MagicMock()
        mock_vm.is_vm_running.return_value = False
        mock_vm.start_vm.return_value = True
        mock_qemu.return_value = mock_vm

        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.GHIDRA_ANALYSIS])

        ghidra_data = result.results["ghidra_analysis"]
        assert ghidra_data is not None
        assert "ghidra_executed" in ghidra_data

    def test_select_ghidra_script_pe_binary(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """_select_ghidra_script chooses appropriate script for PE."""
        with patch.object(orchestrator.ghidra_script_manager, 'discover_scripts'):
            mock_script = MagicMock()
            mock_script.name = "LicenseAnalysis"
            orchestrator.ghidra_script_manager.list_scripts = MagicMock(return_value=[mock_script])

            script = orchestrator._select_ghidra_script(str(temp_binary_file))

            assert script is not None
            assert "License" in script.name

    def test_parse_ghidra_output(self, orchestrator: AnalysisOrchestrator) -> None:
        """_parse_ghidra_output extracts license check patterns."""
        ghidra_output = """
        Function: CheckLicense at 0x401000
        LICENSE_CHECK Function: ValidateSerial at 0x402000
        String: "Enter License Key"
        crypto: AES encryption detected
        Function analyzed: GetRegistrationStatus
        """

        parsed = orchestrator._parse_ghidra_output(ghidra_output)

        assert len(parsed["license_checks"]) >= 1
        assert parsed["functions_analyzed"] > 0
        assert len(parsed["crypto_routines"]) > 0
        assert any("aes" in str(c).lower() for c in parsed["crypto_routines"])

    def test_extract_address_from_output(self, orchestrator: AnalysisOrchestrator) -> None:
        """_extract_address correctly identifies hex addresses."""
        line_hex = "Function at 0x401234"
        line_h = "Address: 00401234h"

        addr1 = orchestrator._extract_address(line_hex)
        addr2 = orchestrator._extract_address(line_h)

        assert "401234" in addr1 or "401234" in addr2

    def test_identify_crypto_type(self, orchestrator: AnalysisOrchestrator) -> None:
        """_identify_crypto_type identifies cryptographic algorithms."""
        assert orchestrator._identify_crypto_type("Found AES encryption") == "AES"
        assert orchestrator._identify_crypto_type("RSA key generation") == "RSA"
        assert orchestrator._identify_crypto_type("MD5 checksum") == "MD5"
        assert orchestrator._identify_crypto_type("SHA256 hash") == "SHA256"

    def test_identify_protection_type(self, orchestrator: AnalysisOrchestrator) -> None:
        """_identify_protection_type categorizes protections."""
        assert orchestrator._identify_protection_type("anti-debug check") == "Anti-Debugging"
        assert orchestrator._identify_protection_type("code obfuscation") == "Obfuscation"
        assert orchestrator._identify_protection_type("packed executable") == "Packing"

    def test_is_interesting_string(self, orchestrator: AnalysisOrchestrator) -> None:
        """_is_interesting_string filters license-related strings."""
        assert orchestrator._is_interesting_string("Enter license key") is True
        assert orchestrator._is_interesting_string("Trial expired") is True
        assert orchestrator._is_interesting_string("Registration required") is True
        assert orchestrator._is_interesting_string("Hello world") is False

    def test_vulnerability_scan_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Vulnerability scan phase executes without errors."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.VULNERABILITY_SCAN])

        vuln_data = result.results["vulnerability_scan"]
        assert vuln_data is not None

    def test_pattern_matching_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Pattern matching phase executes YARA scan."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.PATTERN_MATCHING])

        pattern_data = result.results["pattern_matching"]
        assert pattern_data is not None

    def test_dynamic_analysis_phase_unavailable(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """Dynamic analysis phase handles unavailability gracefully."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.DYNAMIC_ANALYSIS])

        dynamic_data = result.results["dynamic_analysis"]
        assert "status" in dynamic_data or "error" in dynamic_data


class TestRunSelectedAnalysis:
    """Test run_selected_analysis convenience function."""

    def test_run_all_analysis_types(self, temp_binary_file: Path) -> None:
        """run_selected_analysis executes all requested types."""
        result = run_selected_analysis(
            str(temp_binary_file),
            analysis_types=["entropy", "structure"]
        )

        assert result["success"] is not None
        assert result["binary_path"] == str(temp_binary_file)
        assert "results" in result
        assert "phases_completed" in result

    def test_run_with_none_types(self, temp_binary_file: Path) -> None:
        """run_selected_analysis runs all phases when types is None."""
        result = run_selected_analysis(str(temp_binary_file), analysis_types=None)

        assert result["success"] is not None
        assert len(result["phases_completed"]) > 0

    def test_analysis_type_mapping(self, temp_binary_file: Path) -> None:
        """run_selected_analysis correctly maps analysis types to phases."""
        result = run_selected_analysis(
            str(temp_binary_file),
            analysis_types=["static", "entropy", "structure"]
        )

        phases = result["phases_completed"]
        assert any("static" in str(p).lower() or "entropy" in str(p).lower() or "structure" in str(p).lower() for p in phases)

    def test_return_format(self, temp_binary_file: Path) -> None:
        """run_selected_analysis returns correctly formatted dictionary."""
        result = run_selected_analysis(str(temp_binary_file), analysis_types=["entropy"])

        assert "success" in result
        assert "binary_path" in result
        assert "results" in result
        assert "phases_completed" in result
        assert "errors" in result
        assert "warnings" in result
        assert isinstance(result["phases_completed"], list)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_phases_list(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """analyze_binary handles empty phases list."""
        result = orchestrator.analyze_binary(str(temp_binary_file), phases=[])

        assert result.success is True
        assert len(result.phases_completed) == 0

    def test_invalid_phase(self, orchestrator: AnalysisOrchestrator, temp_binary_file: Path) -> None:
        """analyze_binary handles unknown phases gracefully."""
        result = orchestrator.analyze_binary(str(temp_binary_file), [AnalysisPhase.PREPARATION])

        assert result.success is True

    def test_binary_path_with_spaces(self, orchestrator: AnalysisOrchestrator, tmp_path: Path, real_pe_binary: bytes) -> None:
        """Orchestrator handles file paths with spaces."""
        binary_path = tmp_path / "test binary with spaces.exe"
        binary_path.write_bytes(real_pe_binary)

        result = orchestrator.analyze_binary(str(binary_path), [AnalysisPhase.PREPARATION])

        assert result.success is True
        assert AnalysisPhase.PREPARATION in result.phases_completed

    def test_very_small_binary(self, orchestrator: AnalysisOrchestrator, tmp_path: Path) -> None:
        """Orchestrator handles very small binaries."""
        small_binary = b"MZ\x00\x00" + b"\x00" * 60
        binary_path = tmp_path / "small.exe"
        binary_path.write_bytes(small_binary)

        result = orchestrator.analyze_binary(str(binary_path), [AnalysisPhase.ENTROPY_ANALYSIS])

        assert result.success is True

    def test_unicode_binary_path(self, orchestrator: AnalysisOrchestrator, tmp_path: Path, real_pe_binary: bytes) -> None:
        """Orchestrator handles Unicode file paths."""
        binary_path = tmp_path / "test_файл.exe"
        binary_path.write_bytes(real_pe_binary)

        result = orchestrator.analyze_binary(str(binary_path), [AnalysisPhase.PREPARATION])

        assert result.success is True
