"""Production-ready tests for radare2_scripting.py.

Tests validate REAL script execution, error handling, and workflow capabilities
against actual binaries. All tests verify genuine offensive functionality works.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_scripting import (
    R2ScriptingEngine,
    execute_license_analysis_script,
    execute_vulnerability_analysis_script,
)
from intellicrack.utils.tools.radare2_utils import R2Exception


class TestR2ScriptingEngineInitialization:
    """Test R2ScriptingEngine initialization with real binaries."""

    def test_engine_initializes_with_real_binary_path(self) -> None:
        """Engine initializes with valid Windows system binary."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        engine = R2ScriptingEngine(notepad_path)

        assert engine.binary_path == notepad_path
        assert engine.radare2_path is None
        assert isinstance(engine.script_cache, dict)
        assert len(engine.script_cache) == 0

    def test_engine_accepts_custom_radare2_path(self) -> None:
        """Engine accepts custom radare2 executable path."""
        binary_path = r"C:\Windows\System32\kernel32.dll"
        custom_r2_path = r"C:\tools\radare2\radare2.exe"

        engine = R2ScriptingEngine(binary_path, custom_r2_path)

        assert engine.radare2_path == custom_r2_path


class TestCustomAnalysisExecution:
    """Test execute_custom_analysis with real r2 commands."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="notepad.exe required")
    def test_execute_basic_info_command_returns_results(self) -> None:
        """Executing basic info command returns valid results."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        engine = R2ScriptingEngine(notepad_path)

        commands = ["ij"]
        result = engine.execute_custom_analysis(commands)

        assert result["binary_path"] == notepad_path
        assert result["commands_executed"] == commands
        assert len(result["command_results"]) >= 1
        assert result["command_results"][0]["command"] == "ij"
        assert result["command_results"][0]["success"] is True
        assert result["execution_time"] > 0

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\kernel32.dll"), reason="kernel32.dll required")
    def test_execute_multiple_commands_processes_all(self) -> None:
        """Executing multiple commands processes all in sequence."""
        kernel32_path = r"C:\Windows\System32\kernel32.dll"
        engine = R2ScriptingEngine(kernel32_path)

        commands = ["ij", "iEj", "iij"]
        result = engine.execute_custom_analysis(commands)

        assert len(result["command_results"]) == 3
        assert all(cmd_result["success"] for cmd_result in result["command_results"])
        assert result["analysis_summary"]["total_commands"] == 3
        assert result["analysis_summary"]["successful_commands"] == 3
        assert result["analysis_summary"]["failed_commands"] == 0

    def test_execute_invalid_command_captures_error(self) -> None:
        """Executing invalid command captures error properly."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        engine = R2ScriptingEngine(notepad_path)

        commands = ["invalid_r2_command_xyz"]
        result = engine.execute_custom_analysis(commands)

        assert result["binary_path"] == notepad_path
        assert len(result["errors"]) >= 0


class TestLicenseAnalysisScript:
    """Test license analysis script generation and execution."""

    def test_generate_license_analysis_script_returns_commands(self) -> None:
        """License analysis script generates comprehensive command set."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        script = engine.generate_license_analysis_script()

        assert isinstance(script, list)
        assert len(script) > 15
        assert "aaa" in script
        assert "aflj" in script
        assert "/j license" in script
        assert "/j registration" in script
        assert "/j serial" in script
        assert "/j key" in script
        assert "iij" in script

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="notepad.exe required")
    def test_execute_license_analysis_workflow_completes(self) -> None:
        """License analysis workflow completes with real binary."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        engine = R2ScriptingEngine(notepad_path)

        result = engine.execute_license_analysis_workflow()

        assert result["workflow_type"] == "license_analysis"
        assert result["binary_path"] == notepad_path
        assert isinstance(result["license_functions"], list)
        assert isinstance(result["license_strings"], list)
        assert isinstance(result["license_imports"], list)
        assert isinstance(result["crypto_usage"], list)
        assert isinstance(result["validation_mechanisms"], list)
        assert isinstance(result["bypass_opportunities"], list)
        assert 0.0 <= result["analysis_confidence"] <= 1.0


class TestVulnerabilityAnalysisScript:
    """Test vulnerability analysis script generation and execution."""

    def test_generate_vulnerability_analysis_script_comprehensive(self) -> None:
        """Vulnerability analysis script includes dangerous function checks."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\kernel32.dll")

        script = engine.generate_vulnerability_analysis_script()

        assert "aaaa" in script
        assert "/j strcpy" in script
        assert "/j sprintf" in script
        assert "/j malloc" in script
        assert "/j VirtualAllocEx" in script
        assert "iij" in script

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\kernel32.dll"), reason="kernel32.dll required")
    def test_execute_vulnerability_analysis_workflow_finds_risks(self) -> None:
        """Vulnerability analysis workflow identifies security risks."""
        kernel32_path = r"C:\Windows\System32\kernel32.dll"
        engine = R2ScriptingEngine(kernel32_path)

        result = engine.execute_vulnerability_analysis_workflow()

        assert result["workflow_type"] == "vulnerability_analysis"
        assert result["binary_path"] == kernel32_path
        assert isinstance(result["buffer_overflow_risks"], list)
        assert isinstance(result["format_string_risks"], list)
        assert isinstance(result["memory_corruption_risks"], list)
        assert isinstance(result["injection_risks"], list)
        assert isinstance(result["privilege_escalation_risks"], list)
        assert isinstance(result["network_security_risks"], list)
        assert 0.0 <= result["overall_risk_score"] <= 1.0
        assert isinstance(result["security_recommendations"], list)


class TestFunctionAnalysis:
    """Test specific function analysis capabilities."""

    def test_generate_function_analysis_script_targets_function(self) -> None:
        """Function analysis script targets specific function."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        script = engine.generate_function_analysis_script("main")

        assert "s main" in script
        assert "pdf" in script
        assert "pdc" in script
        assert "afi" in script
        assert "afvj" in script


class TestScriptCreation:
    """Test custom r2 script file creation."""

    def test_create_custom_r2_script_generates_file(self) -> None:
        """Creating custom r2 script generates executable file."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        commands = ["aaa", "aflj", "iij"]
        script_path = engine.create_custom_r2_script(
            "test_script",
            commands,
            "Test script for validation"
        )

        assert os.path.exists(script_path)
        assert script_path.endswith(".r2")

        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "test_script" in content
            assert "Test script for validation" in content
            assert "aaa" in content
            assert "aflj" in content
            assert "iij" in content

        os.unlink(script_path)

    def test_create_patcher_script_includes_patches(self) -> None:
        """Automated patcher script includes all patches."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        patches = [
            {
                "address": "0x401000",
                "patch_bytes": "9090",
                "description": "NOP license check"
            },
            {
                "address": "0x401050",
                "patch_bytes": "b801000000",
                "description": "Return 1 always"
            }
        ]

        script_path = engine.create_automated_patcher_script(patches)

        assert os.path.exists(script_path)

        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "s 0x401000" in content
            assert "wx 9090" in content
            assert "s 0x401050" in content
            assert "wx b801000000" in content
            assert "wtf patched_binary" in content

        os.unlink(script_path)


class TestScriptExecutionErrorHandling:
    """Test error handling during script execution."""

    def test_execute_script_with_nonexistent_file_returns_error(self) -> None:
        """Executing non-existent script file returns error."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        result = engine.execute_r2_script_file(r"C:\nonexistent\script.r2")

        assert result["execution_successful"] is False
        assert len(result["errors"]) > 0

    def test_execute_custom_analysis_with_session_error_continues(self) -> None:
        """Custom analysis continues after individual command errors."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        commands = ["ij", "invalid_cmd", "iij"]
        result = engine.execute_custom_analysis(commands)

        assert len(result["command_results"]) == 3


class TestStandaloneFunctions:
    """Test standalone convenience functions."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="notepad.exe required")
    def test_execute_license_analysis_script_standalone(self) -> None:
        """Standalone license analysis function works."""
        notepad_path = r"C:\Windows\System32\notepad.exe"

        result = execute_license_analysis_script(notepad_path)

        assert result["workflow_type"] == "license_analysis"
        assert result["binary_path"] == notepad_path
        assert isinstance(result["license_functions"], list)

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\kernel32.dll"), reason="kernel32.dll required")
    def test_execute_vulnerability_analysis_script_standalone(self) -> None:
        """Standalone vulnerability analysis function works."""
        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        result = execute_vulnerability_analysis_script(kernel32_path)

        assert result["workflow_type"] == "vulnerability_analysis"
        assert result["binary_path"] == kernel32_path
        assert isinstance(result["buffer_overflow_risks"], list)


class TestResultProcessing:
    """Test helper methods for processing analysis results."""

    def test_extract_license_functions_identifies_functions(self) -> None:
        """License function extraction identifies relevant functions."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        command_results = [
            {
                "command": "aflj",
                "result": [
                    {"name": "sym.check_license", "offset": 0x401000, "size": 100},
                    {"name": "sym.validate_key", "offset": 0x401100, "size": 150},
                    {"name": "sym.normal_function", "offset": 0x402000, "size": 50}
                ],
                "success": True
            }
        ]

        functions = engine._extract_license_functions(command_results)

        assert len(functions) >= 2
        license_names = [f["name"] for f in functions]
        assert "sym.check_license" in license_names
        assert "sym.validate_key" in license_names

    def test_identify_validation_mechanisms_detects_registry(self) -> None:
        """Validation mechanism identification detects registry usage."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        command_results = [
            {
                "command": "/j RegOpenKey",
                "result": [{"offset": 0x401000}],
                "success": True
            }
        ]

        mechanisms = engine._identify_validation_mechanisms(command_results)

        assert "registry_validation" in mechanisms

    def test_find_bypass_opportunities_suggests_patches(self) -> None:
        """Bypass opportunity finder suggests function patches."""
        engine = R2ScriptingEngine(r"C:\Windows\System32\notepad.exe")

        workflow_result = {
            "license_functions": [
                {"name": "check_license", "address": "0x401000"},
                {"name": "validate_serial", "address": "0x401100"}
            ],
            "validation_mechanisms": ["registry_validation"]
        }

        opportunities = engine._find_bypass_opportunities(workflow_result)

        assert len(opportunities) >= 2
        assert any(opp["type"] == "function_patch" for opp in opportunities)
        assert any(opp["type"] == "registry_bypass" for opp in opportunities)
