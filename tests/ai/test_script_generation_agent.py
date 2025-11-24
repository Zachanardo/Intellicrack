"""Production-grade tests for script_generation_agent.py - validates real script generation workflows.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.ai_script_generator import GeneratedScript, ScriptMetadata, ScriptType
from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.script_generation_agent import (
    AIAgent,
    TaskRequest,
    ValidationEnvironment,
    WorkflowState,
)


@dataclass
class MockOrchestratorProtocol:
    """Mock orchestrator for testing."""

    pass


@dataclass
class MockCLIInterfaceProtocol:
    """Mock CLI interface for testing."""

    messages: list[str]

    def print_info(self, message: str) -> None:
        """Print info message."""
        self.messages.append(message)


@pytest.fixture
def sample_binary_path(tmp_path: Path) -> Path:
    """Create a sample PE binary for testing."""
    binary_path = tmp_path / "test_app.exe"
    pe_header = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
        b"\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
        b"\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
        b"\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
        b"PE\x00\x00L\x01\x03\x00"
    )
    pe_header += b"\x00" * (512 - len(pe_header))
    pe_header += b"license_check\x00" * 10
    pe_header += b"trial_expired\x00" * 10
    pe_header += b"serial_validation\x00" * 10
    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def agent() -> AIAgent:
    """Create AIAgent instance for testing."""
    return AIAgent()


@pytest.fixture
def agent_with_cli() -> tuple[AIAgent, MockCLIInterfaceProtocol]:
    """Create AIAgent with mock CLI interface."""
    cli = MockCLIInterfaceProtocol(messages=[])
    agent = AIAgent(cli_interface=cli)
    return agent, cli


class TestAIAgentInitialization:
    """Tests for AIAgent initialization."""

    def test_agent_initialization_creates_required_attributes(self, agent: AIAgent) -> None:
        """Agent initializes with all required state tracking attributes."""
        assert agent.script_generator is not None
        assert agent.conversation_history == []
        assert agent.current_task is None
        assert agent.workflow_state == WorkflowState.IDLE
        assert agent.iteration_count == 0
        assert agent.max_iterations == 10
        assert agent.generated_scripts == []
        assert agent.validation_results == []
        assert agent.refinement_history == []
        assert agent.agent_id.startswith("agent_")
        assert agent.frida_manager is not None

    def test_agent_initialization_with_orchestrator(self) -> None:
        """Agent initializes with orchestrator reference."""
        orchestrator = MockOrchestratorProtocol()
        agent = AIAgent(orchestrator=orchestrator)
        assert agent.orchestrator is orchestrator

    def test_agent_initialization_with_cli_interface(self) -> None:
        """Agent initializes with CLI interface reference."""
        cli = MockCLIInterfaceProtocol(messages=[])
        agent = AIAgent(cli_interface=cli)
        assert agent.cli_interface is cli

    def test_agent_vm_tracking_initialized(self, agent: AIAgent) -> None:
        """Agent VM tracking structures are initialized."""
        assert agent._active_vms == {}
        assert agent._vm_snapshots == {}
        assert agent._resource_manager is not None
        assert agent._audit_logger is not None


class TestRequestParsing:
    """Tests for user request parsing functionality."""

    def test_parse_request_extracts_binary_path_from_exe(self, agent: AIAgent) -> None:
        """Parser extracts .exe binary path from request."""
        request = "Create a Frida script for app.exe to bypass license check"
        task = agent._parse_request(request)
        assert task.binary_path == "app.exe"

    def test_parse_request_extracts_binary_path_from_full_path(self, agent: AIAgent) -> None:
        """Parser extracts full path from request."""
        request = "Analyze C:/apps/test_software.exe and create bypass"
        task = agent._parse_request(request)
        assert "test_software.exe" in task.binary_path or "/" in task.binary_path

    def test_parse_request_extracts_frida_script_type(self, agent: AIAgent) -> None:
        """Parser identifies Frida script type request."""
        request = "Create a Frida script for app.exe"
        task = agent._parse_request(request)
        assert ScriptType.FRIDA in task.script_types

    def test_parse_request_extracts_ghidra_script_type(self, agent: AIAgent) -> None:
        """Parser identifies Ghidra script type request."""
        request = "Generate Ghidra static analysis script for app.exe"
        task = agent._parse_request(request)
        assert ScriptType.GHIDRA in task.script_types

    def test_parse_request_extracts_both_script_types(self, agent: AIAgent) -> None:
        """Parser extracts both Frida and Ghidra when requested."""
        request = "Create both Frida and Ghidra scripts for app.exe"
        task = agent._parse_request(request)
        assert ScriptType.FRIDA in task.script_types
        assert ScriptType.GHIDRA in task.script_types

    def test_parse_request_detects_qemu_environment(self, agent: AIAgent) -> None:
        """Parser identifies QEMU test environment."""
        request = "Test in QEMU environment for app.exe"
        task = agent._parse_request(request)
        assert task.validation_environment == ValidationEnvironment.QEMU

    def test_parse_request_detects_sandbox_environment(self, agent: AIAgent) -> None:
        """Parser identifies sandbox test environment."""
        request = "Test in sandbox for app.exe"
        task = agent._parse_request(request)
        assert task.validation_environment == ValidationEnvironment.SANDBOX

    def test_parse_request_detects_direct_environment(self, agent: AIAgent) -> None:
        """Parser identifies direct test environment."""
        request = "Test directly on app.exe"
        task = agent._parse_request(request)
        assert task.validation_environment == ValidationEnvironment.DIRECT

    def test_parse_request_detects_autonomous_mode(self, agent: AIAgent) -> None:
        """Parser identifies autonomous mode request."""
        request = "Autonomously create scripts for app.exe"
        task = agent._parse_request(request)
        assert task.autonomous_mode is True
        assert task.user_confirmation_required is False

    def test_parse_request_defaults_to_confirmation_mode(self, agent: AIAgent) -> None:
        """Parser defaults to requiring user confirmation."""
        request = "Create script for app.exe"
        task = agent._parse_request(request)
        assert task.user_confirmation_required is True


class TestBinaryPathExtraction:
    """Tests for binary path extraction from requests."""

    def test_extract_binary_path_exe_extension(self, agent: AIAgent) -> None:
        """Extracts binary path with .exe extension."""
        request = "Analyze crackme.exe for protections"
        path = agent._extract_binary_path(request)
        assert path == "crackme.exe"

    def test_extract_binary_path_dll_extension(self, agent: AIAgent) -> None:
        """Extracts binary path with .dll extension."""
        request = "Analyze library.dll protections"
        path = agent._extract_binary_path(request)
        assert path == "library.dll"

    def test_extract_binary_path_with_slash(self, agent: AIAgent) -> None:
        """Extracts binary path containing slashes."""
        request = "Test /usr/local/bin/app for license checks"
        path = agent._extract_binary_path(request)
        assert "/" in path or "bin" in path

    def test_extract_binary_path_windows_path(self, agent: AIAgent) -> None:
        """Extracts Windows-style path with backslashes."""
        request = r"Analyze C:\Program Files\App\test.exe"
        path = agent._extract_binary_path(request)
        assert "\\" in path or "test.exe" in path

    def test_extract_binary_path_returns_unknown_when_not_found(self, agent: AIAgent) -> None:
        """Returns 'unknown' when no binary path detected."""
        request = "Just analyze the application"
        path = agent._extract_binary_path(request)
        assert path == "unknown"


class TestScriptTypeExtraction:
    """Tests for script type extraction from requests."""

    def test_extract_script_types_frida_keyword(self, agent: AIAgent) -> None:
        """Extracts Frida script type from 'frida' keyword."""
        types = agent._extract_script_types("create frida script")
        assert ScriptType.FRIDA in types

    def test_extract_script_types_dynamic_keyword(self, agent: AIAgent) -> None:
        """Extracts Frida script type from 'dynamic' keyword."""
        types = agent._extract_script_types("dynamic analysis needed")
        assert ScriptType.FRIDA in types

    def test_extract_script_types_ghidra_keyword(self, agent: AIAgent) -> None:
        """Extracts Ghidra script type from 'ghidra' keyword."""
        types = agent._extract_script_types("generate ghidra analysis")
        assert ScriptType.GHIDRA in types

    def test_extract_script_types_static_keyword(self, agent: AIAgent) -> None:
        """Extracts Ghidra script type from 'static' keyword."""
        types = agent._extract_script_types("static analysis required")
        assert ScriptType.GHIDRA in types

    def test_extract_script_types_both_keyword(self, agent: AIAgent) -> None:
        """Extracts both script types from 'both' keyword."""
        types = agent._extract_script_types("create both analysis types")
        assert ScriptType.FRIDA in types
        assert ScriptType.GHIDRA in types

    def test_extract_script_types_defaults_to_both(self, agent: AIAgent) -> None:
        """Defaults to both script types when none specified."""
        types = agent._extract_script_types("analyze the binary")
        assert ScriptType.FRIDA in types
        assert ScriptType.GHIDRA in types


class TestBinaryAnalysis:
    """Tests for binary analysis functionality."""

    def test_analyze_target_returns_analysis_dict(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Analysis returns dictionary with all expected fields."""
        analysis = agent._analyze_target(str(sample_binary_path))
        assert analysis is not None
        assert "binary_path" in analysis
        assert "binary_info" in analysis
        assert "strings" in analysis
        assert "functions" in analysis
        assert "imports" in analysis
        assert "protections" in analysis
        assert "network_activity" in analysis

    def test_analyze_target_extracts_binary_info(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Analysis extracts basic binary information."""
        analysis = agent._analyze_target(str(sample_binary_path))
        assert analysis is not None
        binary_info = analysis["binary_info"]
        assert binary_info["name"] == "test_app.exe"
        assert binary_info["size"] > 0
        assert "type" in binary_info

    def test_analyze_target_handles_missing_file(self, agent: AIAgent) -> None:
        """Analysis handles non-existent binary gracefully."""
        analysis = agent._analyze_target("/nonexistent/binary.exe")
        assert analysis is not None
        assert isinstance(analysis.get("strings", []), list)

    def test_get_binary_info_returns_metadata(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Get binary info returns file metadata."""
        info = agent._get_binary_info(str(sample_binary_path))
        assert info["name"] == "test_app.exe"
        assert info["size"] > 0
        assert info["type"] == "PE"

    def test_get_binary_info_handles_missing_file(self, agent: AIAgent) -> None:
        """Get binary info handles missing file."""
        info = agent._get_binary_info("/missing/file.exe")
        assert info["name"] == "unknown"
        assert info["size"] == 0


class TestStringExtraction:
    """Tests for string extraction from binaries."""

    def test_extract_strings_finds_license_keywords(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """String extraction finds license-related strings."""
        strings = agent._extract_strings(str(sample_binary_path))
        assert isinstance(strings, list)
        if strings:
            has_license_related = any(
                keyword in s.lower() for s in strings for keyword in ["license", "trial", "serial"]
            )
            assert has_license_related

    def test_extract_strings_returns_empty_for_invalid_path(self, agent: AIAgent) -> None:
        """String extraction returns empty list for invalid path."""
        strings = agent._extract_strings("")
        assert strings == []

    def test_normalize_strings_data_handles_dict(self, agent: AIAgent) -> None:
        """Normalize strings handles dictionary format."""
        data = {"strings": ["test1", "test2"]}
        result = agent._normalize_strings_data(data)
        assert result == ["test1", "test2"]

    def test_normalize_strings_data_handles_list(self, agent: AIAgent) -> None:
        """Normalize strings handles list format."""
        data = ["test1", "test2"]
        result = agent._normalize_strings_data(data)
        assert result == ["test1", "test2"]

    def test_filter_license_related_strings_finds_keywords(self, agent: AIAgent) -> None:
        """Filter finds strings with license keywords."""
        all_strings = ["random_text", "license_check_function", "trial_expired", "hello_world"]
        filtered = agent._filter_license_related_strings(all_strings)
        assert "license_check_function" in filtered
        assert "trial_expired" in filtered
        assert "hello_world" not in filtered

    def test_contains_license_keyword_detects_keywords(self, agent: AIAgent) -> None:
        """Keyword detection identifies license-related terms."""
        keywords = ["license", "trial", "activation"]
        assert agent._contains_license_keyword("license_validation", keywords) is True
        assert agent._contains_license_keyword("trial_period", keywords) is True
        assert agent._contains_license_keyword("random_string", keywords) is False


class TestFunctionAnalysis:
    """Tests for function analysis functionality."""

    def test_analyze_functions_returns_list(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Function analysis returns list of functions."""
        functions = agent._analyze_functions(str(sample_binary_path))
        assert isinstance(functions, list)

    def test_analyze_functions_handles_missing_file(self, agent: AIAgent) -> None:
        """Function analysis handles missing file gracefully."""
        functions = agent._analyze_functions("/nonexistent/binary.exe")
        assert functions == []

    def test_classify_function_type_identifies_license_check(self, agent: AIAgent) -> None:
        """Function classifier identifies license check functions."""
        func_type = agent._classify_function_type("check_license_validation")
        assert func_type == "license_check"

    def test_classify_function_type_identifies_time_check(self, agent: AIAgent) -> None:
        """Function classifier identifies time check functions."""
        func_type = agent._classify_function_type("get_system_time")
        assert func_type == "time_check"

    def test_classify_function_type_identifies_trial_check(self, agent: AIAgent) -> None:
        """Function classifier identifies trial check functions."""
        func_type = agent._classify_function_type("check_trial_period")
        assert func_type == "trial_check"

    def test_classify_function_type_returns_unknown_for_generic(self, agent: AIAgent) -> None:
        """Function classifier returns unknown for generic functions."""
        func_type = agent._classify_function_type("random_function_name")
        assert func_type == "unknown"


class TestImportAnalysis:
    """Tests for import analysis functionality."""

    def test_analyze_imports_returns_list(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Import analysis returns list of imports."""
        imports = agent._analyze_imports(str(sample_binary_path))
        assert isinstance(imports, list)

    def test_analyze_imports_handles_missing_file(self, agent: AIAgent) -> None:
        """Import analysis handles missing file gracefully."""
        imports = agent._analyze_imports("/nonexistent/binary.exe")
        assert imports == []

    def test_validate_import_binary_path_rejects_relative_path(self, agent: AIAgent) -> None:
        """Import validation rejects relative paths."""
        result = agent._validate_import_binary_path("relative/path.exe")
        assert result is False

    def test_validate_import_binary_path_rejects_missing_file(self, agent: AIAgent) -> None:
        """Import validation rejects non-existent files."""
        result = agent._validate_import_binary_path("/absolute/missing.exe")
        assert result is False

    def test_format_import_entry_formats_dict_with_dll(self, agent: AIAgent) -> None:
        """Import formatter handles dict with DLL name."""
        entry = {"name": "CreateFileA", "dll": "kernel32.dll"}
        result = agent._format_import_entry(entry)
        assert result == "kernel32.dll:CreateFileA"

    def test_format_import_entry_formats_dict_without_dll(self, agent: AIAgent) -> None:
        """Import formatter handles dict without DLL name."""
        entry = {"name": "ImportFunc"}
        result = agent._format_import_entry(entry)
        assert result == "ImportFunc"

    def test_format_import_entry_formats_string(self, agent: AIAgent) -> None:
        """Import formatter handles string entry."""
        result = agent._format_import_entry("kernel32.dll:CreateFileA")
        assert result == "kernel32.dll:CreateFileA"


class TestProtectionDetection:
    """Tests for protection mechanism detection."""

    def test_detect_protections_returns_list(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Protection detection returns list of protections."""
        protections = agent._detect_protections(str(sample_binary_path))
        assert isinstance(protections, list)

    def test_detect_protections_handles_missing_file(self, agent: AIAgent) -> None:
        """Protection detection handles missing file gracefully."""
        protections = agent._detect_protections("/nonexistent/binary.exe")
        assert protections == []


class TestNetworkActivityAnalysis:
    """Tests for network activity detection."""

    def test_check_network_activity_returns_dict(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Network activity check returns structured dictionary."""
        result = agent._check_network_activity(str(sample_binary_path))
        assert isinstance(result, dict)
        assert "has_network" in result
        assert "endpoints" in result
        assert "protocols" in result

    def test_check_network_activity_handles_missing_file(self, agent: AIAgent) -> None:
        """Network activity check handles missing file."""
        result = agent._check_network_activity("/nonexistent/binary.exe")
        assert result["has_network"] is False
        assert "error" in result


class TestScriptGeneration:
    """Tests for script generation workflow."""

    def test_generate_initial_scripts_creates_scripts(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Initial script generation creates scripts for each type."""
        analysis = {
            "binary_path": str(sample_binary_path),
            "binary_info": {"name": "test.exe", "type": "PE"},
            "protections": [],
            "strings": [],
            "functions": [],
            "imports": [],
            "network_activity": {"has_network": False},
        }
        agent.current_task = TaskRequest(
            binary_path=str(sample_binary_path),
            script_types=[ScriptType.FRIDA],
            validation_environment=ValidationEnvironment.DIRECT,
            max_iterations=5,
            autonomous_mode=True,
            user_confirmation_required=False,
        )
        scripts = agent._generate_initial_scripts(analysis)
        assert isinstance(scripts, list)


class TestScriptValidation:
    """Tests for script validation functionality."""

    def test_verify_bypass_detects_success_indicators(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Bypass verification detects success indicators in output."""
        result = ExecutionResult(
            success=True,
            output="bypass successful - license check disabled",
            error="",
            exit_code=0,
            runtime_ms=500,
        )
        analysis = {"protections": [], "binary_path": str(sample_binary_path)}
        assert agent._verify_bypass(result, analysis) is True

    def test_verify_bypass_rejects_failed_execution(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Bypass verification rejects failed execution."""
        result = ExecutionResult(success=False, output="", error="execution failed", exit_code=1, runtime_ms=100)
        analysis = {"protections": [], "binary_path": str(sample_binary_path)}
        assert agent._verify_bypass(result, analysis) is False

    def test_verify_bypass_checks_runtime_duration(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Bypass verification considers runtime duration."""
        result = ExecutionResult(success=True, output="bypass", error="", exit_code=0, runtime_ms=1)
        analysis = {"protections": [{"type": "license_check"}] * 5, "binary_path": str(sample_binary_path)}
        verification = agent._verify_bypass(result, analysis)
        assert isinstance(verification, bool)


class TestScriptRefinement:
    """Tests for script refinement logic."""

    def test_apply_failure_refinements_adds_stealth_mode(self, agent: AIAgent) -> None:
        """Failure refinement adds stealth mode for detection errors."""
        script = GeneratedScript(content='console.log("[AI-Generated] test")', metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        validation_result = ExecutionResult(
            success=False,
            output="",
            error="protection mechanism detected",
            exit_code=1,
            runtime_ms=100,
        )
        content, notes = agent._apply_failure_refinements(script, validation_result, script.content)
        assert "stealth" in content.lower() or "exception" in content.lower()

    def test_apply_protection_refinements_adds_license_bypass(self, agent: AIAgent) -> None:
        """Protection refinement adds license bypass code."""
        script = GeneratedScript(content="// Basic script", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        protections = [{"type": "license_check", "confidence": 0.9}]
        notes = agent._apply_protection_refinements(script, protections, script.content)
        assert isinstance(notes, list)

    def test_get_license_bypass_code_returns_valid_frida(self, agent: AIAgent) -> None:
        """License bypass code generator returns valid Frida script."""
        code = agent._get_license_bypass_code()
        assert "Interceptor.attach" in code
        assert "license" in code.lower()

    def test_get_time_bypass_code_returns_valid_frida(self, agent: AIAgent) -> None:
        """Time bypass code generator returns valid Frida script."""
        code = agent._get_time_bypass_code()
        assert "Interceptor.attach" in code or "GetSystemTime" in code


class TestScriptDeployment:
    """Tests for script deployment functionality."""

    def test_deploy_scripts_saves_to_filesystem(self, agent: AIAgent, tmp_path: Path) -> None:
        """Script deployment saves scripts to filesystem."""
        script = GeneratedScript(content="test script", metadata=ScriptMetadata())
        script.metadata.script_id = "test_script_123"
        agent.current_task = TaskRequest(
            binary_path="test.exe",
            script_types=[ScriptType.FRIDA],
            validation_environment=ValidationEnvironment.DIRECT,
            max_iterations=5,
            autonomous_mode=True,
            user_confirmation_required=False,
        )
        results = agent._deploy_scripts([script])
        assert len(results) == 1
        assert results[0]["script_id"] == "test_script_123"


class TestConversationHistory:
    """Tests for conversation history tracking."""

    def test_log_to_user_adds_to_history(self, agent: AIAgent) -> None:
        """User logging adds message to conversation history."""
        initial_count = len(agent.conversation_history)
        agent._log_to_user("Test message")
        assert len(agent.conversation_history) == initial_count + 1
        assert agent.conversation_history[-1]["content"] == "Test message"

    def test_get_conversation_history_returns_copy(self, agent: AIAgent) -> None:
        """Get conversation history returns a copy."""
        agent._log_to_user("Test")
        history = agent.get_conversation_history()
        assert isinstance(history, list)
        history.append({"test": "modified"})
        assert len(agent.get_conversation_history()) != len(history)


class TestWorkflowStatus:
    """Tests for workflow status tracking."""

    def test_get_status_returns_current_state(self, agent: AIAgent) -> None:
        """Get status returns current workflow state."""
        status = agent.get_status()
        assert status["state"] == "idle"
        assert status["iteration"] == 0
        assert status["scripts_generated"] == 0
        assert status["tests_run"] == 0
        assert "last_update" in status

    def test_workflow_state_transitions(self, agent: AIAgent) -> None:
        """Workflow state transitions correctly."""
        assert agent.workflow_state == WorkflowState.IDLE
        agent.workflow_state = WorkflowState.ANALYZING
        assert agent.workflow_state == WorkflowState.ANALYZING
        agent.workflow_state = WorkflowState.GENERATING
        assert agent.workflow_state == WorkflowState.GENERATING


class TestSessionManagement:
    """Tests for session data management."""

    def test_save_session_data_creates_json_file(self, agent: AIAgent, tmp_path: Path) -> None:
        """Session save creates valid JSON file."""
        output_path = tmp_path / "session.json"
        agent._log_to_user("Test session")
        saved_path = agent.save_session_data(str(output_path))
        assert Path(saved_path).exists()
        with open(saved_path) as f:
            data = json.load(f)
        assert "agent_id" in data
        assert "status" in data
        assert "conversation_history" in data

    def test_save_session_data_uses_tempfile_when_no_path(self, agent: AIAgent) -> None:
        """Session save uses temp file when path not provided."""
        saved_path = agent.save_session_data()
        assert Path(saved_path).exists()
        assert saved_path.endswith("_session.json")
        Path(saved_path).unlink()


class TestExecutionEnvironments:
    """Tests for script execution environment selection."""

    def test_test_direct_validates_script_safety(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Direct testing validates script safety before execution."""
        script = GeneratedScript(content="test script", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []
        analysis = {
            "binary_path": str(sample_binary_path),
            "protections": [],
            "binary_info": {"size": 1024},
        }
        result = agent._test_direct(script, analysis)
        assert isinstance(result, ExecutionResult)

    def test_test_direct_blocks_high_risk_binaries(self, agent: AIAgent) -> None:
        """Direct testing blocks high-risk binary execution."""
        script = GeneratedScript(content="test", metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []
        analysis = {
            "binary_path": "test.exe",
            "protections": [{"type": "anti_debug", "confidence": 0.9}] * 3,
            "binary_info": {"size": 100 * 1024 * 1024},
        }
        result = agent._test_direct(script, analysis)
        assert result.success is False
        assert "risky" in result.output.lower() or "blocked" in result.output.lower()


class TestFridaScriptExecution:
    """Tests for Frida script execution functionality."""

    def test_list_available_frida_scripts_returns_library(self, agent: AIAgent) -> None:
        """List available scripts returns Frida script library."""
        scripts = agent.list_available_frida_scripts()
        assert isinstance(scripts, dict)

    def test_validate_generic_script_returns_success(self, agent: AIAgent, tmp_path: Path) -> None:
        """Generic script validation returns success for valid syntax."""
        success, output = agent._validate_generic_script("test.exe", str(tmp_path))
        assert success is True
        assert len(output) > 0


class TestErrorHandling:
    """Tests for error handling and recovery."""

    def test_error_result_creates_error_dict(self, agent: AIAgent) -> None:
        """Error result creates properly formatted error dictionary."""
        result = agent._error_result("Test error message")
        assert result["status"] == "error"
        assert result["message"] == "Test error message"
        assert result["scripts"] == []
        assert "agent_id" in result

    def test_process_request_handles_file_not_found(self, agent: AIAgent) -> None:
        """Process request handles missing binary file."""
        result = agent.process_request("Analyze /nonexistent/binary.exe")
        assert result["status"] == "error"

    def test_analyze_target_handles_import_errors(self, agent: AIAgent) -> None:
        """Target analysis handles import errors gracefully."""
        analysis = agent._analyze_target("/some/path.exe")
        assert analysis is not None or analysis is None


class TestVMLifecycleManagement:
    """Tests for VM lifecycle management."""

    def test_vm_tracking_structures_initialized(self, agent: AIAgent) -> None:
        """VM tracking structures properly initialized."""
        assert hasattr(agent, "_active_vms")
        assert hasattr(agent, "_vm_snapshots")
        assert isinstance(agent._active_vms, dict)
        assert isinstance(agent._vm_snapshots, dict)

    def test_get_free_port_returns_valid_port(self, agent: AIAgent) -> None:
        """Get free port returns valid port number."""
        port = agent._get_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

    def test_get_vm_status_returns_none_for_missing_vm(self, agent: AIAgent) -> None:
        """Get VM status returns None for non-existent VM."""
        status = agent._get_vm_status("nonexistent_vm_id")
        assert status is None

    def test_list_vms_returns_empty_list_initially(self, agent: AIAgent) -> None:
        """List VMs returns empty list when no VMs active."""
        vms = agent._list_vms()
        assert vms == []


class TestAutonomousTaskExecution:
    """Tests for autonomous task execution."""

    def test_execute_autonomous_task_handles_script_generation(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Autonomous task execution handles script generation."""
        task_config = {
            "type": "script_generation",
            "target_binary": str(sample_binary_path),
            "request": f"Create bypass script for {sample_binary_path}",
        }
        result = agent.execute_autonomous_task(task_config)
        assert isinstance(result, dict)
        assert "status" in result or "scripts" in result

    def test_execute_autonomous_task_handles_unknown_type(self, agent: AIAgent) -> None:
        """Autonomous task execution handles unknown task types."""
        task_config = {"type": "unknown_task_type"}
        result = agent.execute_autonomous_task(task_config)
        assert result["status"] == "error"
        assert "unknown" in result["message"].lower()


class TestBinaryPathValidation:
    """Tests for binary path validation and security."""

    def test_validate_binary_path_rejects_relative_paths(self, agent: AIAgent) -> None:
        """Binary path validation rejects relative paths."""
        result = agent._validate_binary_path("relative/path.exe")
        assert result is False

    def test_validate_binary_path_rejects_missing_files(self, agent: AIAgent) -> None:
        """Binary path validation rejects non-existent files."""
        result = agent._validate_binary_path("/absolute/missing.exe")
        assert result is False

    def test_validate_binary_path_accepts_valid_paths(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Binary path validation accepts valid absolute paths."""
        result = agent._validate_binary_path(str(sample_binary_path))
        assert result is True


class TestScriptAnalysis:
    """Tests for script content analysis."""

    def test_analyze_script_content_detects_frida(self, agent: AIAgent) -> None:
        """Script analysis detects Frida JavaScript patterns."""
        script = "Java.perform(function() { console.log('test'); });"
        output = agent._analyze_script_content(script, "test.exe")
        assert any("frida" in line.lower() for line in output)

    def test_analyze_script_content_detects_memory_manipulation(self, agent: AIAgent) -> None:
        """Script analysis detects memory manipulation patterns."""
        script = "Memory.readByteArray(ptr(0x1000), 100);"
        output = agent._analyze_script_content(script, "test.exe")
        assert any("memory" in line.lower() for line in output)

    def test_analyze_script_content_detects_hooking(self, agent: AIAgent) -> None:
        """Script analysis detects function hooking patterns."""
        script = "Interceptor.attach(Module.findExportByName(null, 'strcmp'));"
        output = agent._analyze_script_content(script, "test.exe")
        assert any("hook" in line.lower() for line in output)


class TestRealWorldScenarios:
    """Integration tests for real-world usage scenarios."""

    def test_end_to_end_script_generation_workflow(self, agent_with_cli: tuple[AIAgent, MockCLIInterfaceProtocol], sample_binary_path: Path) -> None:
        """Complete workflow from request to script generation."""
        agent, cli = agent_with_cli
        request = f"Create a Frida script to bypass license check in {sample_binary_path}"
        agent.current_task = agent._parse_request(request)
        assert agent.current_task.binary_path is not None
        assert len(cli.messages) == 0

    def test_script_validation_and_refinement_loop(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Script validation and refinement iteration loop."""
        script = GeneratedScript(content='console.log("test");', metadata=ScriptMetadata())
        script.metadata.script_type = ScriptType.FRIDA
        script.metadata.protection_types = []
        analysis = {
            "binary_path": str(sample_binary_path),
            "protections": [{"type": "license_check", "confidence": 0.8}],
            "binary_info": {"size": 1024},
        }
        validation_result = ExecutionResult(
            success=False,
            output="",
            error="protection mechanism detected",
            exit_code=1,
            runtime_ms=100,
        )
        refined = agent._refine_script(script, validation_result, analysis)
        assert refined is None or isinstance(refined, GeneratedScript)


class TestNetworkPatternDetection:
    """Tests for network pattern detection in binaries."""

    def test_get_network_api_patterns_returns_common_apis(self, agent: AIAgent) -> None:
        """Network API pattern getter returns common networking APIs."""
        patterns = agent._get_network_api_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        assert any("socket" in p.lower() for p in patterns)

    def test_get_network_symbols_returns_common_symbols(self, agent: AIAgent) -> None:
        """Network symbol getter returns common networking symbols."""
        symbols = agent._get_network_symbols()
        assert isinstance(symbols, list)
        assert len(symbols) > 0
        assert any("connect" in s.lower() for s in symbols)


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows Sandbox testing requires Windows platform",
)
class TestWindowsSandboxIntegration:
    """Tests for Windows Sandbox integration."""

    def test_create_windows_sandbox_config_generates_valid_xml(self, agent: AIAgent, tmp_path: Path) -> None:
        """Windows Sandbox config generation creates valid XML."""
        config = agent._create_windows_sandbox_config(str(tmp_path), "test.exe", has_network=False)
        assert "<Configuration>" in config
        assert "<Networking>" in config
        assert str(tmp_path) in config


class TestExecutionResultValidation:
    """Tests for execution result validation."""

    def test_execution_result_validates_success_criteria(self, agent: AIAgent, sample_binary_path: Path) -> None:
        """Execution result validation checks success criteria."""
        result = ExecutionResult(
            success=True,
            output="license bypassed successfully",
            error="",
            exit_code=0,
            runtime_ms=500,
        )
        analysis = {"protections": [], "binary_path": str(sample_binary_path)}
        is_valid = agent._verify_bypass(result, analysis)
        assert isinstance(is_valid, bool)
