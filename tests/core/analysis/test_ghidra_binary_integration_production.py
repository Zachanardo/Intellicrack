"""Production tests for ghidra_binary_integration module.

This module tests the GhidraBinaryIntegration class which provides integration
between Intellicrack and Ghidra scripts for license validation analysis, protection
detection, crypto routine analysis, and keygen generation.

Copyright (C) 2025 Zachary Flint
"""

import struct
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.analysis.ghidra_binary_integration import GhidraBinaryIntegration


def create_minimal_pe(path: Path, machine_type: int = 0x014C) -> Path:
    """Create a minimal valid PE file for testing.

    Args:
        path: Path where PE file will be created
        machine_type: PE machine type (0x014C for x86, 0x8664 for x64)

    Returns:
        Path to created PE file
    """
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        machine_type,
        1,
        0x60000000,
        0,
        0,
        224,
        0x0102,
    )

    optional_header = struct.pack(
        "<HHBBIIIIIHHHHHHIIIIHHIIIIIIII",
        0x010B,
        0,
        0,
        0x1000,
        0,
        0,
        0x1000,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        0,
        0,
        0,
        0,
        4,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )

    data_directories = b"\x00" * (16 * 8)

    section_name = b".text\x00\x00\x00"
    section_header = section_name + struct.pack(
        "<IIIIHHI",
        0x1000,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0xE0000020,
    )

    pe_content = (
        dos_header
        + pe_signature
        + file_header
        + optional_header
        + data_directories
        + section_header
    )

    pe_content = pe_content.ljust(0x200, b"\x00")
    pe_content += b"\x90" * 0x200

    path.write_bytes(pe_content)
    return path


@pytest.fixture
def mock_ghidra_path(tmp_path: Path) -> Path:
    """Create mock Ghidra installation directory."""
    ghidra_dir = tmp_path / "ghidra"
    ghidra_dir.mkdir()

    support_dir = ghidra_dir / "support"
    support_dir.mkdir()

    analyzer_script = support_dir / "analyzeHeadless.bat"
    analyzer_script.write_text("@echo off\necho Mock Ghidra Headless Analyzer\n")

    scripts_dir = ghidra_dir / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    scripts_dir.mkdir(parents=True)

    return ghidra_dir


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test binary for analysis."""
    binary_path = tmp_path / "test_app.exe"
    return create_minimal_pe(binary_path)


@pytest.fixture
def mock_script_runner() -> Mock:
    """Create mock GhidraScriptRunner for testing."""
    runner = Mock()
    runner.run_script = Mock(
        return_value={
            "success": True,
            "validation_functions": 3,
            "function_count": 42,
        }
    )
    runner.list_available_scripts = Mock(return_value=[])
    runner._get_script = Mock(return_value=None)
    runner.refresh_scripts = Mock(return_value=0)
    return runner


class TestGhidraBinaryIntegrationInitialization:
    """Test GhidraBinaryIntegration initialization."""

    def test_initialization_with_valid_path(self, mock_ghidra_path: Path) -> None:
        """GhidraBinaryIntegration initializes with valid Ghidra path."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner"):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            assert integration.ghidra_path == mock_ghidra_path
            assert integration.script_runner is not None
            assert integration.logger is not None

    def test_ghidra_path_attribute_preserved(self, mock_ghidra_path: Path) -> None:
        """Ghidra path is correctly stored during initialization."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner"):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            assert str(integration.ghidra_path) == str(mock_ghidra_path)


class TestLicenseValidationAnalysis:
    """Test license validation analysis functionality."""

    def test_basic_license_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """analyze_license_validation detects license validation routines."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "validation_functions": 5,
                "serial_check_function": "CheckSerialNumber",
                "license_check_function": "ValidateLicense",
            }

            result = integration.analyze_license_validation(test_binary, deep_analysis=False)

            assert result["success"] is True
            assert result["validation_functions"] == 5
            assert "serial_check_function" in result
            mock_script_runner.run_script.assert_called_once()

    def test_deep_license_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """Deep analysis mode uses enhanced licensing script."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "validation_functions": 8,
                "algorithm_details": {"type": "RSA-2048"},
            }

            result = integration.analyze_license_validation(test_binary, deep_analysis=True)

            assert result["success"] is True
            assert result["validation_functions"] == 8
            call_args = mock_script_runner.run_script.call_args
            assert "enhanced_licensing_analysis" in str(call_args)

    def test_license_analysis_error_handling(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """License analysis handles script execution errors."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.side_effect = RuntimeError("Script execution failed")

            result = integration.analyze_license_validation(test_binary)

            assert result["success"] is False
            assert "error" in result
            assert "Script execution failed" in result["error"]


class TestProtectionDetection:
    """Test protection scheme detection."""

    def test_detect_vmprotect(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """detect_protections identifies VMProtect."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "vmprotect_detected": True,
                "themida_detected": False,
                "enigma_detected": False,
            }

            result = integration.detect_protections(test_binary)

            assert result["success"] is True
            assert "VMProtect" in result["protections"]
            assert len(result["protections"]) == 1

    def test_detect_multiple_protections(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """detect_protections identifies multiple protection schemes."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "vmprotect_detected": True,
                "themida_detected": True,
                "enigma_detected": True,
            }

            result = integration.detect_protections(test_binary)

            assert result["success"] is True
            assert len(result["protections"]) == 3
            assert "VMProtect" in result["protections"]
            assert "Themida" in result["protections"]
            assert "Enigma" in result["protections"]

    def test_detect_no_protections(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """detect_protections returns empty list when no protections found."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "vmprotect_detected": False,
                "themida_detected": False,
                "enigma_detected": False,
            }

            result = integration.detect_protections(test_binary)

            assert result["success"] is True
            assert len(result["protections"]) == 0


class TestCryptoAnalysis:
    """Test cryptographic routine analysis."""

    def test_analyze_crypto_routines(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """analyze_crypto_routines detects cryptographic algorithms."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.side_effect = [
                {"success": True, "algorithms": ["AES-256", "SHA-256"]},
                {"success": True, "custom_crypto": ["custom_xor"]},
            ]

            result = integration.analyze_crypto_routines(test_binary)

            assert result["success"] is True
            assert "AES-256" in result["standard_algorithms"]
            assert "SHA-256" in result["standard_algorithms"]
            assert "custom_xor" in result["custom_crypto"]

    def test_crypto_analysis_error_handling(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """Crypto analysis handles errors gracefully."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.side_effect = Exception("Analysis failed")

            result = integration.analyze_crypto_routines(test_binary)

            assert result["success"] is False
            assert "error" in result


class TestKeygenTemplateGeneration:
    """Test keygen template generation."""

    def test_generate_keygen_template(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """generate_keygen_template creates valid template from license algorithm."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "algorithm_type": "RSA-2048",
                "validation_function": "ValidateSerial",
                "keygen_code": "def generate_key(): pass",
            }

            result = integration.generate_keygen_template(test_binary)

            assert result["success"] is True
            assert result["algorithm_type"] == "RSA-2048"
            assert "keygen_code" in result


class TestDeobfuscationFeatures:
    """Test deobfuscation capabilities."""

    def test_deobfuscate_control_flow(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """deobfuscate_control_flow removes obfuscation."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "blocks_deobfuscated": 15,
                "junk_code_removed": 42,
            }

            result = integration.deobfuscate_control_flow(test_binary)

            assert result["success"] is True
            assert result["blocks_deobfuscated"] == 15

    def test_decrypt_strings(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """decrypt_strings decrypts obfuscated strings."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "decrypted_strings": ["License key invalid", "Registration required"],
            }

            result = integration.decrypt_strings(test_binary)

            assert result["success"] is True
            assert len(result["decrypted_strings"]) == 2


class TestAntiAnalysisDetection:
    """Test anti-analysis technique detection."""

    def test_detect_anti_debug(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """detect_anti_analysis identifies anti-debug techniques."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "anti_debug": True,
                "anti_vm": False,
                "anti_dump": False,
            }

            result = integration.detect_anti_analysis(test_binary)

            assert result["success"] is True
            assert "anti-debug" in result["techniques"]
            assert len(result["techniques"]) == 1

    def test_detect_multiple_anti_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """detect_anti_analysis identifies multiple techniques."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "anti_debug": True,
                "anti_vm": True,
                "anti_dump": True,
            }

            result = integration.detect_anti_analysis(test_binary)

            assert result["success"] is True
            assert len(result["techniques"]) == 3


class TestComprehensiveAnalysis:
    """Test comprehensive analysis workflow."""

    def test_perform_comprehensive_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """perform_comprehensive_analysis runs full analysis."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "function_count": 128,
                "imports": 45,
                "exports": 12,
            }

            result = integration.perform_comprehensive_analysis(test_binary)

            assert result["success"] is True
            assert result["function_count"] == 128


class TestLicensingCrackWorkflow:
    """Test complete licensing crack workflow."""

    def test_licensing_crack_workflow_unprotected(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """perform_licensing_crack_workflow executes full crack workflow."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.run_script.return_value = {
                "success": True,
                "vmprotect_detected": False,
                "themida_detected": False,
                "enigma_detected": False,
                "validation_functions": 3,
                "algorithms": ["MD5"],
                "custom_crypto": [],
                "decrypted_strings": ["License"],
                "anti_debug": False,
                "anti_vm": False,
                "anti_dump": False,
            }

            result = integration.perform_licensing_crack_workflow(test_binary)

            assert result["success"] is True
            assert "stages" in result
            assert "protection_detection" in result["stages"]
            assert "license_analysis" in result["stages"]
            assert "crypto_analysis" in result["stages"]
            assert "keygen_generation" in result["stages"]

    def test_licensing_crack_workflow_with_packer(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        mock_script_runner: Mock,
    ) -> None:
        """Workflow includes unpacking when packer detected."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            responses = [
                {"success": True, "vmprotect_detected": True, "themida_detected": False, "enigma_detected": False},
                {"success": True, "oep": 0x401000},
                {"success": True, "validation_functions": 5},
                {"success": True, "algorithms": []},
                {"success": True, "custom_crypto": []},
                {"success": True, "algorithm_type": "custom"},
                {"success": True, "decrypted_strings": []},
                {"success": True, "anti_debug": False, "anti_vm": False, "anti_dump": False},
            ]

            mock_script_runner.run_script.side_effect = responses

            result = integration.perform_licensing_crack_workflow(test_binary)

            assert result["success"] is True
            assert "unpacking" in result["stages"]


class TestScriptManagement:
    """Test script discovery and management."""

    def test_get_available_scripts(
        self,
        mock_ghidra_path: Path,
        mock_script_runner: Mock,
    ) -> None:
        """get_available_scripts returns list of discovered scripts."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.list_available_scripts.return_value = [
                {"name": "licensing_analysis", "language": "python"},
                {"name": "crypto_finder", "language": "java"},
            ]

            scripts = integration.get_available_scripts()

            assert len(scripts) == 2
            assert scripts[0]["name"] == "licensing_analysis"

    def test_refresh_scripts(
        self,
        mock_ghidra_path: Path,
        mock_script_runner: Mock,
    ) -> None:
        """refresh_scripts rediscovers scripts from filesystem."""
        with patch("intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner", return_value=mock_script_runner):
            integration = GhidraBinaryIntegration(mock_ghidra_path)

            mock_script_runner.refresh_scripts.return_value = 5

            count = integration.refresh_scripts()

            assert count == 5
            mock_script_runner.refresh_scripts.assert_called_once()
