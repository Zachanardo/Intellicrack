"""Production tests for AI Wrapper CLI module.

These tests validate that AI-controllable wrapper correctly:
- Manages user confirmation for AI actions
- Executes CLI commands with proper validation
- Generates functional Frida scripts for hooking and bypassing
- Generates functional Ghidra scripts for analysis
- Tracks action history and session data
- Implements risk assessment for operations
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.cli.ai_wrapper import (
    AI_TOOLS,
    ActionType,
    ConfirmationManager,
    IntellicrackAIInterface,
    PendingAction,
    create_ai_prompt,
)


class TestConfirmationManager:
    """Test confirmation system for AI actions."""

    def test_confirmation_manager_initializes(self) -> None:
        manager = ConfirmationManager()

        assert manager.pending_actions == {}
        assert manager.action_history == []
        assert manager.auto_approve_low_risk is False

    def test_auto_approve_low_risk_enabled(self) -> None:
        manager = ConfirmationManager(auto_approve_low_risk=True)

        action = PendingAction(
            action_id="test_123",
            action_type=ActionType.ANALYSIS,
            command=["test", "command"],
            description="Test action",
            risk_level="low",
            potential_impacts=[],
            timestamp=0.0,
        )

        approved = manager.request_confirmation(action)

        assert approved is True
        assert len(manager.action_history) == 0

    def test_action_history_tracking(self) -> None:
        manager = ConfirmationManager()

        action = PendingAction(
            action_id="test_456",
            action_type=ActionType.ANALYSIS,
            command=["analyze"],
            description="Test analysis",
            risk_level="low",
            potential_impacts=[],
            timestamp=0.0,
        )

        with patch("builtins.input", return_value="y"):
            approved = manager.request_confirmation(action)

        assert approved is True
        assert len(manager.action_history) == 1
        assert manager.action_history[0]["approved"] is True

    def test_rejection_tracking(self) -> None:
        manager = ConfirmationManager()

        action = PendingAction(
            action_id="test_789",
            action_type=ActionType.PATCHING,
            command=["patch"],
            description="Test patching",
            risk_level="high",
            potential_impacts=["Binary modification"],
            timestamp=0.0,
        )

        with patch("builtins.input", return_value="n"):
            approved = manager.request_confirmation(action)

        assert approved is False
        assert len(manager.action_history) == 1
        assert manager.action_history[0]["approved"] is False


class TestIntellicrackAIInterface:
    """Test AI interface functionality."""

    def test_interface_initializes(self) -> None:
        interface = IntellicrackAIInterface()

        assert interface.confirmation_manager is not None
        assert interface.session_id is not None
        assert len(interface.session_id) > 0
        assert interface.current_analysis == {}

    def test_determine_action_type_analysis(self) -> None:
        interface = IntellicrackAIInterface()

        action_type = interface._determine_action_type(["--comprehensive"])

        assert action_type == ActionType.ANALYSIS

    def test_determine_action_type_patching(self) -> None:
        interface = IntellicrackAIInterface()

        action_type = interface._determine_action_type(["--apply-patch"])

        assert action_type == ActionType.PATCHING

    def test_determine_action_type_bypass(self) -> None:
        interface = IntellicrackAIInterface()

        action_type = interface._determine_action_type(["--bypass-tpm"])

        assert action_type == ActionType.BYPASS_OPERATION

    def test_determine_action_type_plugin(self) -> None:
        interface = IntellicrackAIInterface()

        action_type = interface._determine_action_type(["--plugin-run"])

        assert action_type == ActionType.PLUGIN_EXECUTION

    def test_determine_risk_level_low(self) -> None:
        interface = IntellicrackAIInterface()

        risk = interface._determine_risk_level(["--comprehensive"])

        assert risk == "low"

    def test_determine_risk_level_high(self) -> None:
        interface = IntellicrackAIInterface()

        risk = interface._determine_risk_level(["--apply-patch"])

        assert risk == "high"

    def test_determine_risk_level_medium(self) -> None:
        interface = IntellicrackAIInterface()

        risk = interface._determine_risk_level(["--suggest-patches"])

        assert risk == "medium"

    def test_get_potential_impacts_patching(self) -> None:
        interface = IntellicrackAIInterface()

        impacts = interface._get_potential_impacts(["--apply-patch"])

        assert "Binary file will be modified" in impacts[0]

    def test_get_potential_impacts_bypass(self) -> None:
        interface = IntellicrackAIInterface()

        impacts = interface._get_potential_impacts(["--bypass-tpm"])

        assert any("protection mechanisms will be bypassed" in impact for impact in impacts)

    def test_execute_command_cancelled(self) -> None:
        interface = IntellicrackAIInterface()

        with patch.object(interface.confirmation_manager, "request_confirmation", return_value=False):
            result = interface.execute_command(["test"], "Test command")

        assert result["status"] == "cancelled"
        assert "User declined" in result["message"]

    def test_execute_command_success(self) -> None:
        interface = IntellicrackAIInterface()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"test": "success"}'
        mock_result.stderr = ""

        with patch.object(interface.confirmation_manager, "request_confirmation", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = interface.execute_command(["--format", "json"], "Test")

        assert result["status"] == "success"
        assert result["exit_code"] == 0

    def test_analyze_binary_basic(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"file_type": "PE", "success": True})
        mock_result.stderr = ""

        with patch.object(interface.confirmation_manager, "request_confirmation", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = interface.analyze_binary(str(test_binary))

        assert result["status"] == "success"

    def test_suggest_patches(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "patch_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"patches": []})
        mock_result.stderr = ""

        with patch.object(interface.confirmation_manager, "request_confirmation", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = interface.suggest_patches(str(test_binary))

        assert result["status"] == "success"

    def test_session_summary(self) -> None:
        interface = IntellicrackAIInterface()

        interface.confirmation_manager.action_history.extend(
            [
                {"action": MagicMock(), "approved": True, "timestamp": 0.0},
                {"action": MagicMock(), "approved": False, "timestamp": 1.0},
                {"action": MagicMock(), "approved": True, "timestamp": 2.0},
            ]
        )

        summary = interface.get_session_summary()

        assert summary["session_id"] == interface.session_id
        assert summary["total_actions"] == 3
        assert summary["approved_actions"] == 2
        assert summary["declined_actions"] == 1


class TestFridaScriptGeneration:
    """Test Frida script generation for runtime hooking."""

    def test_generate_frida_hook_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "target.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(str(test_binary), None, "hook")

        assert result["status"] == "success"
        assert result["script_type"] == "hook"
        assert result["platform"] == "frida"
        assert result["language"] == "javascript"
        assert len(result["script"]) > 0

        script = result["script"]
        assert "Interceptor.attach" in script
        assert "license" in script.lower()
        assert "onEnter" in script
        assert "onLeave" in script

    def test_generate_frida_hook_script_with_target_function(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "licensed.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(str(test_binary), "CheckLicense", "hook")

        assert result["status"] == "success"
        assert result["target_function"] == "CheckLicense"

        script = result["script"]
        assert "CheckLicense" in script

    def test_generate_frida_bypass_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "protected.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(str(test_binary), None, "bypass")

        assert result["status"] == "success"
        assert result["script_type"] == "bypass"

        script = result["script"]
        assert "IsDebuggerPresent" in script
        assert "Interceptor.replace" in script or "Interceptor.attach" in script

    def test_generate_frida_trace_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "api_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(str(test_binary), None, "trace")

        assert result["status"] == "success"
        assert result["script_type"] == "trace"

        script = result["script"]
        assert "RegOpenKeyExW" in script or "RegQueryValueExW" in script
        assert "GetVolumeInformationW" in script or "CryptVerifySignature" in script

    def test_generate_frida_spoof_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "hwid_check.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(str(test_binary), None, "spoof")

        assert result["status"] == "success"
        assert result["script_type"] == "spoof"

        script = result["script"]
        assert "GetVolumeInformationW" in script or "GetComputerNameW" in script
        assert "spoofedData" in script
        assert "GetSystemTime" in script or "GetLocalTime" in script

    def test_generate_frida_script_without_binary_path(self) -> None:
        interface = IntellicrackAIInterface()
        result = interface.generate_frida_script(None, None, "hook")

        assert result["status"] == "error"
        assert "Binary path is required" in result["message"]


class TestGhidraScriptGeneration:
    """Test Ghidra script generation for static analysis."""

    def test_generate_ghidra_comprehensive_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "analyze_target.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(str(test_binary), "comprehensive")

        assert result["status"] == "success"
        assert result["script_type"] == "comprehensive"
        assert result["platform"] == "ghidra"
        assert result["language"] == "java"
        assert "class_name" in result

        script = result["script"]
        assert "GhidraScript" in script
        assert "analyzeLicensingFunctions" in script
        assert "analyzeCryptoFunctions" in script
        assert "analyzeStrings" in script
        assert "analyzeImports" in script

    def test_generate_ghidra_licensing_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "licensed_app.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(str(test_binary), "licensing")

        assert result["status"] == "success"
        assert result["script_type"] == "licensing"

        script = result["script"]
        assert "license" in script.lower()
        assert "FunctionManager" in script
        assert "FunctionIterator" in script

    def test_generate_ghidra_crypto_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "crypto_app.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(str(test_binary), "crypto")

        assert result["status"] == "success"
        assert result["script_type"] == "crypto"

        script = result["script"]
        assert "CRYPTO_CONSTANTS" in script
        assert "AES" in script or "MD5" in script or "SHA" in script
        assert "Memory" in script

    def test_generate_ghidra_strings_script(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "string_analysis.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(str(test_binary), "strings")

        assert result["status"] == "success"
        assert result["script_type"] == "strings"

        script = result["script"]
        assert "StringDataType" in script or "UnicodeDataType" in script
        assert "DataIterator" in script

    def test_generate_ghidra_script_without_binary_path(self) -> None:
        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(None, "comprehensive")

        assert result["status"] == "error"
        assert "Binary path is required" in result["message"]

    def test_ghidra_script_class_name_sanitized(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "test-app!@#.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()
        result = interface.generate_ghidra_script(str(test_binary), "comprehensive")

        assert result["status"] == "success"

        class_name = result["class_name"]
        assert class_name.replace("_", "").isalnum()


class TestAIToolsConfiguration:
    """Test AI tools configuration and metadata."""

    def test_ai_tools_defined(self) -> None:
        assert "analyze_binary" in AI_TOOLS
        assert "suggest_patches" in AI_TOOLS
        assert "apply_patch" in AI_TOOLS
        assert "execute_command" in AI_TOOLS

    def test_ai_tools_have_descriptions(self) -> None:
        for tool_name, tool_config in AI_TOOLS.items():
            assert "description" in tool_config
            assert "parameters" in tool_config
            assert len(tool_config["description"]) > 0

    def test_create_ai_prompt_returns_valid_string(self) -> None:
        prompt = create_ai_prompt()

        assert isinstance(prompt, str)
        assert len(prompt) > 0
        assert "analyze_binary" in prompt
        assert "suggest_patches" in prompt
        assert "High-risk actions require user confirmation" in prompt


class TestEndToEndScenarios:
    """Test complete AI-driven workflows."""

    def test_analyze_and_patch_workflow(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "workflow_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 100)

        interface = IntellicrackAIInterface()

        mock_analyze_result = MagicMock()
        mock_analyze_result.returncode = 0
        mock_analyze_result.stdout = json.dumps({"protections": ["vmprotect"]})
        mock_analyze_result.stderr = ""

        with patch.object(interface.confirmation_manager, "request_confirmation", return_value=True):
            with patch("subprocess.run", return_value=mock_analyze_result):
                analyze_result = interface.analyze_binary(str(test_binary), ["comprehensive"])
                assert analyze_result["status"] == "success"

        summary = interface.get_session_summary()
        assert summary["total_actions"] >= 1

    def test_frida_script_generation_workflow(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "frida_workflow.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()

        hook_script = interface.generate_frida_script(str(test_binary), "CheckLicense", "hook")
        assert hook_script["status"] == "success"
        assert "CheckLicense" in hook_script["script"]

        bypass_script = interface.generate_frida_script(str(test_binary), None, "bypass")
        assert bypass_script["status"] == "success"

        trace_script = interface.generate_frida_script(str(test_binary), None, "trace")
        assert trace_script["status"] == "success"

        spoof_script = interface.generate_frida_script(str(test_binary), None, "spoof")
        assert spoof_script["status"] == "success"

    def test_ghidra_script_generation_workflow(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "ghidra_workflow.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        interface = IntellicrackAIInterface()

        comprehensive = interface.generate_ghidra_script(str(test_binary), "comprehensive")
        assert comprehensive["status"] == "success"
        assert comprehensive["language"] == "java"

        licensing = interface.generate_ghidra_script(str(test_binary), "licensing")
        assert licensing["status"] == "success"

        crypto = interface.generate_ghidra_script(str(test_binary), "crypto")
        assert crypto["status"] == "success"

        strings = interface.generate_ghidra_script(str(test_binary), "strings")
        assert strings["status"] == "success"
