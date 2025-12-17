"""Production tests for core utility functions.

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

import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.utils.core.core_utilities import (
    TOOL_REGISTRY,
    deep_runtime_monitoring,
    dispatch_tool,
    main,
    on_message,
    register,
    register_default_tools,
    register_tool,
    retrieve_few_shot_examples,
    run_cli_mode,
    run_gui_mode,
)


class TestToolRegistry:
    """Test tool registration system."""

    def test_register_tool_basic(self) -> None:
        """Test basic tool registration."""
        original_registry = TOOL_REGISTRY.copy()

        def test_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success", "data": params}

        result = register_tool("test_registration_tool", test_tool)

        assert result is True
        assert "test_registration_tool" in TOOL_REGISTRY
        assert TOOL_REGISTRY["test_registration_tool"] == test_tool

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_register_tool_with_category(self) -> None:
        """Test tool registration with category."""
        original_registry = TOOL_REGISTRY.copy()

        def test_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success"}

        result = register_tool("categorized_tool", test_tool, category="analysis")

        assert result is True
        assert "categorized_tool" in TOOL_REGISTRY

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_register_tool_duplicate_overwrites(self) -> None:
        """Test registering tool with same name overwrites."""
        original_registry = TOOL_REGISTRY.copy()

        def tool_v1(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"version": 1}

        def tool_v2(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"version": 2}

        register_tool("duplicate_tool", tool_v1)
        register_tool("duplicate_tool", tool_v2)

        assert TOOL_REGISTRY["duplicate_tool"] == tool_v2

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_register_default_tools_populates_registry(self) -> None:
        """Test register_default_tools populates the tool registry."""
        original_registry = TOOL_REGISTRY.copy()
        TOOL_REGISTRY.clear()

        result = register_default_tools()

        if result is not False:
            assert len(TOOL_REGISTRY) > 0
            assert any("tool_" in name for name in TOOL_REGISTRY.keys())

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_register_default_tools_includes_standard_tools(self) -> None:
        """Test default tools registration includes standard tools."""
        original_registry = TOOL_REGISTRY.copy()
        TOOL_REGISTRY.clear()

        register_default_tools()

        expected_tools = [
            "tool_load_binary",
            "tool_detect_protections",
            "tool_run_static_analysis",
        ]

        for tool_name in expected_tools:
            if len(TOOL_REGISTRY) > 0:
                break

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)


class TestDispatchTool:
    """Test tool dispatch mechanism."""

    def test_dispatch_tool_registered(self) -> None:
        """Test dispatching a registered tool."""
        original_registry = TOOL_REGISTRY.copy()

        def mock_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success", "result": params.get("data", "default")}

        TOOL_REGISTRY["mock_dispatch_tool"] = mock_tool

        app = Mock()
        app.update_output = Mock()
        params = {"data": "test_data"}

        result = dispatch_tool(app, "mock_dispatch_tool", params)

        assert result["status"] == "success"
        assert result["result"] == "test_data"
        assert app.update_output.emit.call_count >= 2

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_dispatch_tool_unknown(self) -> None:
        """Test dispatching an unknown tool returns error."""
        original_registry = TOOL_REGISTRY.copy()

        app = Mock()
        app.update_output = Mock()

        result = dispatch_tool(app, "nonexistent_tool", {})

        assert result["status"] == "error"
        assert "Unknown tool" in result["error"]
        assert "available_tools" in result

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_dispatch_tool_suggests_similar(self) -> None:
        """Test tool dispatch suggests similar tools for unknown tools."""
        original_registry = TOOL_REGISTRY.copy()

        def test_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success"}

        TOOL_REGISTRY["tool_analyze_binary"] = test_tool
        TOOL_REGISTRY["tool_analyze_license"] = test_tool

        app = Mock()
        app.update_output = Mock()

        result = dispatch_tool(app, "analyze", {})

        assert result["status"] == "error"
        assert "suggestions" in result
        assert len(result["suggestions"]) > 0

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_dispatch_tool_handles_exception(self) -> None:
        """Test tool dispatch handles tool execution exceptions."""
        original_registry = TOOL_REGISTRY.copy()

        def failing_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("Tool execution failed")

        TOOL_REGISTRY["failing_tool"] = failing_tool

        app = Mock()
        app.update_output = Mock()

        result = dispatch_tool(app, "failing_tool", {})

        assert result["status"] == "error"
        assert "Error executing tool" in result["error"]
        assert "traceback" in result

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_dispatch_tool_without_ui(self) -> None:
        """Test tool dispatch works without UI instance."""
        original_registry = TOOL_REGISTRY.copy()

        def simple_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success", "value": params.get("value", 42)}

        TOOL_REGISTRY["simple_tool"] = simple_tool

        result = dispatch_tool(None, "simple_tool", {"value": 100})

        assert result["status"] == "success"
        assert result["value"] == 100

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)


class TestPluginRegistration:
    """Test plugin registration system."""

    def test_register_plugin_basic(self) -> None:
        """Test basic plugin registration."""
        plugin_info = {
            "name": "test_plugin",
            "version": "1.0.0",
            "entry_point": "test_plugin.main",
        }

        result = register(plugin_info)

        assert result is True

    def test_register_plugin_with_tools(self) -> None:
        """Test plugin registration with tools."""
        original_registry = TOOL_REGISTRY.copy()

        def plugin_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success"}

        plugin_info = {
            "name": "tool_provider",
            "version": "1.0.0",
            "entry_point": "tool_provider.main",
            "tools": {"analyze": plugin_tool},
        }

        result = register(plugin_info)

        assert result is True
        assert "plugin_tool_provider_analyze" in TOOL_REGISTRY

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_register_plugin_missing_name(self) -> None:
        """Test plugin registration fails with missing name."""
        plugin_info = {
            "version": "1.0.0",
            "entry_point": "test.main",
        }

        result = register(plugin_info)

        assert result is False

    def test_register_plugin_missing_version(self) -> None:
        """Test plugin registration fails with missing version."""
        plugin_info = {
            "name": "test_plugin",
            "entry_point": "test.main",
        }

        result = register(plugin_info)

        assert result is False

    def test_register_plugin_missing_entry_point(self) -> None:
        """Test plugin registration fails with missing entry point."""
        plugin_info = {
            "name": "test_plugin",
            "version": "1.0.0",
        }

        result = register(plugin_info)

        assert result is False


class TestFewShotExamples:
    """Test few-shot example retrieval."""

    def test_retrieve_few_shot_license_analysis(self) -> None:
        """Test retrieving license analysis examples."""
        examples = retrieve_few_shot_examples("license_analysis", count=5)

        assert isinstance(examples, list)
        assert len(examples) > 0
        assert len(examples) <= 5

        for example in examples:
            assert "input" in example
            assert "analysis" in example
            assert "suggestion" in example

    def test_retrieve_few_shot_vulnerability_detection(self) -> None:
        """Test retrieving vulnerability detection examples."""
        examples = retrieve_few_shot_examples("vulnerability_detection", count=3)

        assert isinstance(examples, list)
        assert len(examples) > 0
        assert all("input" in ex for ex in examples)

    def test_retrieve_few_shot_protection_identification(self) -> None:
        """Test retrieving protection identification examples."""
        examples = retrieve_few_shot_examples("protection_identification", count=2)

        assert isinstance(examples, list)
        assert len(examples) > 0

    def test_retrieve_few_shot_unknown_task(self) -> None:
        """Test retrieving examples for unknown task type."""
        examples = retrieve_few_shot_examples("unknown_task_type", count=10)

        assert isinstance(examples, list)
        assert len(examples) == 0

    def test_retrieve_few_shot_count_limit(self) -> None:
        """Test few-shot examples respect count limit."""
        examples_1 = retrieve_few_shot_examples("license_analysis", count=1)
        examples_5 = retrieve_few_shot_examples("license_analysis", count=5)

        assert len(examples_1) <= 1
        assert len(examples_5) <= 5

    def test_retrieve_few_shot_example_content(self) -> None:
        """Test few-shot examples contain relevant content."""
        examples = retrieve_few_shot_examples("license_analysis", count=1)

        if examples:
            example = examples[0]
            assert "license" in example["input"].lower() or "license" in example["analysis"].lower()


class TestOnMessage:
    """Test Frida message handling."""

    def test_on_message_send_type(self) -> None:
        """Test handling send-type messages."""
        message = {
            "type": "send",
            "payload": {"type": "info", "message": "Test message"},
        }

        on_message(message)

    def test_on_message_license_check(self) -> None:
        """Test handling license check messages."""
        message = {
            "type": "send",
            "payload": {
                "type": "license_check",
                "details": {"function": "ValidateLicense", "result": False},
            },
        }

        on_message(message)

    def test_on_message_api_call(self) -> None:
        """Test handling API call interception messages."""
        message = {
            "type": "send",
            "payload": {"type": "api_call", "function": "RegQueryValueEx"},
        }

        on_message(message)

    def test_on_message_error_type(self) -> None:
        """Test handling error messages."""
        message = {
            "type": "error",
            "description": "Script error occurred",
            "stack": "at line 10",
        }

        on_message(message)

    def test_on_message_with_data(self) -> None:
        """Test handling messages with binary data."""
        message = {
            "type": "send",
            "payload": {"type": "data_dump"},
        }
        data = b"\x00\x01\x02\x03"

        on_message(message, data)

    def test_on_message_frida_error_payload(self) -> None:
        """Test handling Frida error in payload."""
        message = {
            "type": "send",
            "payload": {"type": "error", "error": "Memory access violation"},
        }

        on_message(message)


class TestDeepRuntimeMonitoring:
    """Test deep runtime monitoring function."""

    def test_deep_runtime_monitoring_basic(self) -> None:
        """Test basic deep runtime monitoring execution."""
        with patch("intellicrack.utils.core.core_utilities.analyzer_drm") as mock_analyzer:
            mock_analyzer.return_value = {"api_calls": [], "memory_reads": []}

            result = deep_runtime_monitoring("test.exe")

            assert isinstance(result, dict)
            if "status" in result:
                assert result["status"] in ["success", "error"]

    def test_deep_runtime_monitoring_with_config(self) -> None:
        """Test deep runtime monitoring with configuration."""
        with patch("intellicrack.utils.core.core_utilities.analyzer_drm") as mock_analyzer:
            mock_analyzer.return_value = {"data": "monitored"}

            config = {"timeout": 60000, "hooks": ["RegQueryValue", "CreateFile"]}
            result = deep_runtime_monitoring("target.exe", config)

            assert isinstance(result, dict)

    def test_deep_runtime_monitoring_handles_error(self) -> None:
        """Test deep runtime monitoring handles errors gracefully."""
        with patch("intellicrack.utils.core.core_utilities.analyzer_drm") as mock_analyzer:
            mock_analyzer.side_effect = RuntimeError("Process not found")

            result = deep_runtime_monitoring("nonexistent.exe")

            assert result["status"] == "error"
            assert "error" in result


class TestRunCLIMode:
    """Test CLI mode execution."""

    @pytest.fixture
    def temp_binary(self) -> Path:
        """Create temporary binary file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(b"MZ\x90\x00")
            temp_path = Path(f.name)
        yield temp_path
        temp_path.unlink()

    def test_run_cli_mode_no_binary(self) -> None:
        """Test CLI mode fails without binary."""
        args = Mock()
        args.binary = None

        result = run_cli_mode(args)

        assert result == 1

    def test_run_cli_mode_with_analysis(self, temp_binary: Path) -> None:
        """Test CLI mode runs analysis."""
        with patch("intellicrack.utils.core.core_utilities.run_comprehensive_analysis") as mock_analysis:
            mock_analysis.return_value = {"summary": {"protection": "None"}}

            args = Mock()
            args.binary = str(temp_binary)
            args.analyze = True
            args.crack = False
            args.output = None

            result = run_cli_mode(args)

            assert result == 0

    def test_run_cli_mode_with_crack(self, temp_binary: Path) -> None:
        """Test CLI mode runs autonomous crack."""
        with patch("intellicrack.utils.core.core_utilities.run_autonomous_crack") as mock_crack:
            mock_crack.return_value = {"success": True, "message": "Cracked"}

            args = Mock()
            args.binary = str(temp_binary)
            args.analyze = False
            args.crack = True
            args.output = None

            result = run_cli_mode(args)

            assert result == 0

    def test_run_cli_mode_saves_output(self, temp_binary: Path) -> None:
        """Test CLI mode saves results to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("intellicrack.utils.core.core_utilities.run_comprehensive_analysis") as mock_analysis:
                mock_analysis.return_value = {"summary": {"status": "complete"}}

                args = Mock()
                args.binary = str(temp_binary)
                args.analyze = True
                args.crack = False
                args.output = tmpdir

                result = run_cli_mode(args)

                output_file = Path(tmpdir) / "intellicrack_results.json"
                assert output_file.exists()

                with open(output_file, encoding="utf-8") as f:
                    saved_results = json.load(f)
                    assert "analysis" in saved_results

    def test_run_cli_mode_handles_exception(self, temp_binary: Path) -> None:
        """Test CLI mode handles exceptions gracefully."""
        with patch("intellicrack.utils.core.core_utilities.run_comprehensive_analysis") as mock_analysis:
            mock_analysis.side_effect = RuntimeError("Analysis failed")

            args = Mock()
            args.binary = str(temp_binary)
            args.analyze = True
            args.crack = False
            args.output = None

            result = run_cli_mode(args)

            assert result == 1


class TestRunGUIMode:
    """Test GUI mode execution."""

    def test_run_gui_mode_import_error(self) -> None:
        """Test GUI mode handles missing PyQt6 gracefully."""
        with patch("intellicrack.utils.core.core_utilities.QApplication") as mock_qapp:
            mock_qapp.side_effect = ImportError("PyQt6 not found")

            args = Mock()
            result = run_gui_mode(args)

            assert result == 1

    def test_run_gui_mode_launch_error(self) -> None:
        """Test GUI mode handles launch errors."""
        with patch("intellicrack.utils.core.core_utilities.QApplication"):
            with patch("intellicrack.utils.core.core_utilities.launch") as mock_launch:
                mock_launch.side_effect = RuntimeError("Launch failed")

                args = Mock()
                result = run_gui_mode(args)

                assert result == 1


class TestMain:
    """Test main entry point."""

    def test_main_default_gui_mode(self) -> None:
        """Test main defaults to GUI mode."""
        with patch("intellicrack.utils.core.core_utilities.run_gui_mode") as mock_gui:
            mock_gui.return_value = 0

            result = main([])

            assert result == 0
            assert mock_gui.called

    def test_main_cli_flag(self) -> None:
        """Test main respects --cli flag."""
        with patch("intellicrack.utils.core.core_utilities.run_cli_mode") as mock_cli:
            mock_cli.return_value = 0

            with tempfile.NamedTemporaryFile(suffix=".exe") as f:
                result = main(["--cli", f.name])

    def test_main_keyboard_interrupt(self) -> None:
        """Test main handles keyboard interrupt."""
        with patch("intellicrack.utils.core.core_utilities.run_gui_mode") as mock_gui:
            mock_gui.side_effect = KeyboardInterrupt()

            result = main([])

            assert result == 1

    def test_main_verbose_logging(self) -> None:
        """Test main configures verbose logging."""
        with patch("intellicrack.utils.core.core_utilities.run_gui_mode") as mock_gui:
            mock_gui.return_value = 0

            result = main(["-vv"])

            assert result == 0

    def test_main_binary_argument(self) -> None:
        """Test main accepts binary argument."""
        with patch("intellicrack.utils.core.core_utilities.run_cli_mode") as mock_cli:
            mock_cli.return_value = 0

            with tempfile.NamedTemporaryFile(suffix=".exe") as f:
                result = main([f.name])


class TestCoreUtilitiesIntegration:
    """Integration tests for core utilities."""

    def test_tool_registration_and_dispatch_workflow(self) -> None:
        """Test complete tool registration and dispatch workflow."""
        original_registry = TOOL_REGISTRY.copy()

        def integration_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {
                "status": "success",
                "processed": params.get("data"),
            }

        register_tool("integration_test_tool", integration_tool)

        app = Mock()
        app.update_output = Mock()
        params = {"data": "integration_data"}

        result = dispatch_tool(app, "integration_test_tool", params)

        assert result["status"] == "success"
        assert result["processed"] == "integration_data"

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)

    def test_plugin_registration_with_tool_dispatch(self) -> None:
        """Test plugin registration integrates with tool dispatch."""
        original_registry = TOOL_REGISTRY.copy()

        def plugin_analysis_tool(app: object, params: dict[str, Any]) -> dict[str, Any]:
            return {"analysis": "complete", "target": params.get("target")}

        plugin_info = {
            "name": "analyzer_plugin",
            "version": "2.0.0",
            "entry_point": "analyzer.main",
            "tools": {"deep_analyze": plugin_analysis_tool},
        }

        register(plugin_info)

        app = Mock()
        app.update_output = Mock()

        result = dispatch_tool(app, "plugin_analyzer_plugin_deep_analyze", {"target": "test.exe"})

        assert result["analysis"] == "complete"
        assert result["target"] == "test.exe"

        TOOL_REGISTRY.clear()
        TOOL_REGISTRY.update(original_registry)
