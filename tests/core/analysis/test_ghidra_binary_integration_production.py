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

import pytest

from intellicrack.core.analysis.ghidra_binary_integration import GhidraBinaryIntegration


class FakeGhidraScriptRunner:
    """Real test double for GhidraScriptRunner with complete behavior tracking."""

    def __init__(self) -> None:
        self.run_script_calls: list[tuple[str, Path, dict[str, Any]]] = []
        self.list_available_scripts_calls: int = 0
        self.refresh_scripts_calls: int = 0
        self._run_script_responses: list[dict[str, Any]] = []
        self._run_script_exceptions: list[Exception | None] = []
        self._list_scripts_response: list[dict[str, str]] = []
        self._refresh_scripts_count: int = 0
        self._current_response_index: int = 0

    def set_run_script_response(self, response: dict[str, Any]) -> None:
        """Configure single response for run_script."""
        self._run_script_responses = [response]
        self._run_script_exceptions = [None]
        self._current_response_index = 0

    def set_run_script_responses(self, responses: list[dict[str, Any]]) -> None:
        """Configure multiple responses for run_script."""
        self._run_script_responses = responses
        self._run_script_exceptions = [None] * len(responses)
        self._current_response_index = 0

    def set_run_script_exception(self, exception: Exception) -> None:
        """Configure run_script to raise exception."""
        self._run_script_responses = []
        self._run_script_exceptions = [exception]
        self._current_response_index = 0

    def set_list_available_scripts_response(self, scripts: list[dict[str, str]]) -> None:
        """Configure list_available_scripts response."""
        self._list_scripts_response = scripts

    def set_refresh_scripts_count(self, count: int) -> None:
        """Configure refresh_scripts return value."""
        self._refresh_scripts_count = count

    def run_script(
        self, script_name: str, binary_path: Path, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Track run_script calls and return configured response."""
        actual_params = params or {}
        self.run_script_calls.append((script_name, binary_path, actual_params))

        if self._current_response_index < len(self._run_script_exceptions):
            exc = self._run_script_exceptions[self._current_response_index]
            if exc is not None:
                self._current_response_index += 1
                raise exc

        if self._current_response_index < len(self._run_script_responses):
            response = self._run_script_responses[self._current_response_index]
            self._current_response_index += 1
            return response

        return {"success": True}

    def list_available_scripts(self) -> list[dict[str, str]]:
        """Track list_available_scripts calls and return configured response."""
        self.list_available_scripts_calls += 1
        return self._list_scripts_response

    def refresh_scripts(self) -> int:
        """Track refresh_scripts calls and return configured count."""
        self.refresh_scripts_calls += 1
        return self._refresh_scripts_count

    def _get_script(self, script_name: str) -> Path | None:
        """Stub for internal script lookup."""
        return None

    def assert_run_script_called_once(self) -> None:
        """Verify run_script was called exactly once."""
        assert len(self.run_script_calls) == 1, f"Expected 1 call, got {len(self.run_script_calls)}"

    def assert_run_script_call_count(self, expected: int) -> None:
        """Verify run_script was called expected number of times."""
        actual = len(self.run_script_calls)
        assert actual == expected, f"Expected {expected} calls, got {actual}"

    def get_last_run_script_call(self) -> tuple[str, Path, dict[str, Any]]:
        """Get the last run_script call arguments."""
        assert len(self.run_script_calls) > 0, "No run_script calls recorded"
        return self.run_script_calls[-1]


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
def fake_script_runner() -> FakeGhidraScriptRunner:
    """Create fake GhidraScriptRunner for testing."""
    runner = FakeGhidraScriptRunner()
    runner.set_run_script_response({
        "success": True,
        "validation_functions": 3,
        "function_count": 42,
    })
    return runner


class TestGhidraBinaryIntegrationInitialization:
    """Test GhidraBinaryIntegration initialization."""

    def test_initialization_with_valid_path(
        self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GhidraBinaryIntegration initializes with valid Ghidra path."""
        fake_runner = FakeGhidraScriptRunner()

        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        assert integration.ghidra_path == mock_ghidra_path
        assert integration.script_runner is not None
        assert integration.logger is not None

    def test_ghidra_path_attribute_preserved(
        self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ghidra path is correctly stored during initialization."""
        fake_runner = FakeGhidraScriptRunner()

        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        assert str(integration.ghidra_path) == str(mock_ghidra_path)


class TestLicenseValidationAnalysis:
    """Test license validation analysis functionality."""

    def test_basic_license_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """analyze_license_validation detects license validation routines."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "validation_functions": 5,
            "serial_check_function": "CheckSerialNumber",
            "license_check_function": "ValidateLicense",
        })

        result = integration.analyze_license_validation(test_binary, deep_analysis=False)

        assert result["success"] is True
        assert result["validation_functions"] == 5
        assert "serial_check_function" in result
        fake_script_runner.assert_run_script_called_once()

    def test_deep_license_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Deep analysis mode uses enhanced licensing script."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "validation_functions": 8,
            "algorithm_details": {"type": "RSA-2048"},
        })

        result = integration.analyze_license_validation(test_binary, deep_analysis=True)

        assert result["success"] is True
        assert result["validation_functions"] == 8
        script_name, _, _ = fake_script_runner.get_last_run_script_call()
        assert "enhanced_licensing_analysis" in script_name

    def test_license_analysis_error_handling(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """License analysis handles script execution errors."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_exception(RuntimeError("Script execution failed"))

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
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_protections identifies VMProtect."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "vmprotect_detected": True,
            "themida_detected": False,
            "enigma_detected": False,
        })

        result = integration.detect_protections(test_binary)

        assert result["success"] is True
        assert "VMProtect" in result["protections"]
        assert len(result["protections"]) == 1

    def test_detect_multiple_protections(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_protections identifies multiple protection schemes."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "vmprotect_detected": True,
            "themida_detected": True,
            "enigma_detected": True,
        })

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
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_protections returns empty list when no protections found."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "vmprotect_detected": False,
            "themida_detected": False,
            "enigma_detected": False,
        })

        result = integration.detect_protections(test_binary)

        assert result["success"] is True
        assert len(result["protections"]) == 0


class TestCryptoAnalysis:
    """Test cryptographic routine analysis."""

    def test_analyze_crypto_routines(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """analyze_crypto_routines detects cryptographic algorithms."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_responses([
            {"success": True, "algorithms": ["AES-256", "SHA-256"]},
            {"success": True, "custom_crypto": ["custom_xor"]},
        ])

        result = integration.analyze_crypto_routines(test_binary)

        assert result["success"] is True
        assert "AES-256" in result["standard_algorithms"]
        assert "SHA-256" in result["standard_algorithms"]
        assert "custom_xor" in result["custom_crypto"]

    def test_crypto_analysis_error_handling(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Crypto analysis handles errors gracefully."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_exception(Exception("Analysis failed"))

        result = integration.analyze_crypto_routines(test_binary)

        assert result["success"] is False
        assert "error" in result


class TestKeygenTemplateGeneration:
    """Test keygen template generation."""

    def test_generate_keygen_template(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """generate_keygen_template creates valid template from license algorithm."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "algorithm_type": "RSA-2048",
            "validation_function": "ValidateSerial",
            "keygen_code": "def generate_key(): pass",
        })

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
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """deobfuscate_control_flow removes obfuscation."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "blocks_deobfuscated": 15,
            "junk_code_removed": 42,
        })

        result = integration.deobfuscate_control_flow(test_binary)

        assert result["success"] is True
        assert result["blocks_deobfuscated"] == 15

    def test_decrypt_strings(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """decrypt_strings decrypts obfuscated strings."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "decrypted_strings": ["License key invalid", "Registration required"],
        })

        result = integration.decrypt_strings(test_binary)

        assert result["success"] is True
        assert len(result["decrypted_strings"]) == 2


class TestAntiAnalysisDetection:
    """Test anti-analysis technique detection."""

    def test_detect_anti_debug(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_anti_analysis identifies anti-debug techniques."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "anti_debug": True,
            "anti_vm": False,
            "anti_dump": False,
        })

        result = integration.detect_anti_analysis(test_binary)

        assert result["success"] is True
        assert "anti-debug" in result["techniques"]
        assert len(result["techniques"]) == 1

    def test_detect_multiple_anti_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_anti_analysis identifies multiple techniques."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "anti_debug": True,
            "anti_vm": True,
            "anti_dump": True,
        })

        result = integration.detect_anti_analysis(test_binary)

        assert result["success"] is True
        assert len(result["techniques"]) == 3


class TestComprehensiveAnalysis:
    """Test comprehensive analysis workflow."""

    def test_perform_comprehensive_analysis(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """perform_comprehensive_analysis runs full analysis."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
            "success": True,
            "function_count": 128,
            "imports": 45,
            "exports": 12,
        })

        result = integration.perform_comprehensive_analysis(test_binary)

        assert result["success"] is True
        assert result["function_count"] == 128


class TestLicensingCrackWorkflow:
    """Test complete licensing crack workflow."""

    def test_licensing_crack_workflow_unprotected(
        self,
        mock_ghidra_path: Path,
        test_binary: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """perform_licensing_crack_workflow executes full crack workflow."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_run_script_response({
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
        })

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
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Workflow includes unpacking when packer detected."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

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

        fake_script_runner.set_run_script_responses(responses)

        result = integration.perform_licensing_crack_workflow(test_binary)

        assert result["success"] is True
        assert "unpacking" in result["stages"]


class TestScriptManagement:
    """Test script discovery and management."""

    def test_get_available_scripts(
        self,
        mock_ghidra_path: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """get_available_scripts returns list of discovered scripts."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_list_available_scripts_response([
            {"name": "licensing_analysis", "language": "python"},
            {"name": "crypto_finder", "language": "java"},
        ])

        scripts = integration.get_available_scripts()

        assert len(scripts) == 2
        assert scripts[0]["name"] == "licensing_analysis"

    def test_refresh_scripts(
        self,
        mock_ghidra_path: Path,
        fake_script_runner: FakeGhidraScriptRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """refresh_scripts rediscovers scripts from filesystem."""
        def fake_runner_init(ghidra_path: Path) -> FakeGhidraScriptRunner:
            return fake_script_runner

        monkeypatch.setattr(
            "intellicrack.core.analysis.ghidra_binary_integration.GhidraScriptRunner",
            fake_runner_init
        )

        integration = GhidraBinaryIntegration(mock_ghidra_path)

        fake_script_runner.set_refresh_scripts_count(5)

        count = integration.refresh_scripts()

        assert count == 5
        assert fake_script_runner.refresh_scripts_calls == 1
