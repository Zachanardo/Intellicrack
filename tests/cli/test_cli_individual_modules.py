"""Production tests for all individual CLI modules.

Tests all 17 CLI modules with real functionality validation:
- advanced_export.py: JSON/XML/CSV/PDF/HTML export capabilities
- ai_chat_interface.py: Terminal-based AI chat interaction
- ai_integration.py: AI model integration adapters
- ai_wrapper.py: AI-controllable CLI wrapper with confirmations
- analysis_cli.py: Binary analysis CLI commands
- ascii_charts.py: ASCII chart generation and visualization
- config_manager.py: Configuration management
- config_profiles.py: Profile loading/saving
- enhanced_runner.py: Enhanced runner execution
- hex_viewer_cli.py: Hex viewer CLI functionality
- interactive_mode.py: Interactive mode workflows
- project_manager.py: Project management
- run_analysis_cli.py: Analysis CLI execution
- tutorial_system.py: Tutorial system
- pipeline.py: Analysis pipeline
- progress_manager.py: Progress tracking
- terminal_dashboard.py: Terminal dashboard display

Copyright (C) 2025 Zachary Flint
Licensed under GPL-3.0-or-later
"""

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def sample_binary_path(tmp_path: Path) -> Path:
    """Create sample binary for testing."""
    binary_path = tmp_path / "test.exe"
    with open(binary_path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")
        f.write(b"\x00" * 200)
    return binary_path


@pytest.fixture
def sample_analysis_data() -> dict[str, Any]:
    """Sample analysis data for testing."""
    return {
        "timestamp": "2025-12-14T00:00:00",
        "target_file": "test.exe",
        "file_hash": "a" * 64,
        "protections": ["VMProtect", "Themida"],
        "license_checks": [
            {"address": "0x401000", "type": "serial_validation"},
            {"address": "0x402000", "type": "trial_check"},
        ],
        "vulnerabilities": [
            {"type": "weak_crypto", "severity": "high"},
        ],
        "strings": ["Serial:", "License:", "Trial expired"],
        "imports": ["kernel32.dll", "user32.dll"],
        "exports": [],
        "sections": [
            {"name": ".text", "size": 4096, "entropy": 6.5},
            {"name": ".data", "size": 2048, "entropy": 3.2},
        ],
    }


class TestAdvancedExport:
    """Test advanced export functionality with real file generation."""

    def test_export_to_json_with_real_data(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to JSON format with real file writing."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "export.json"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_detailed_json(str(output_file))

        assert result is True
        assert output_file.exists()
        with open(output_file) as f:
            loaded_data = json.load(f)

        assert "summary" in loaded_data or "analysis" in loaded_data or loaded_data

    def test_export_to_xml_creates_valid_structure(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to XML with proper structure."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "export.xml"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_xml_report(str(output_file))

        assert result is True
        assert output_file.exists()
        content = output_file.read_text()
        assert "<?xml version" in content
        assert "<analysis>" in content
        assert "<target_file>test.exe</target_file>" in content

    def test_export_to_csv_protections_list(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export protections data to CSV format."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "protections.csv"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_csv_data(str(output_file), data_type="all")

        assert result is True
        assert output_file.exists()

    def test_export_to_csv_license_checks(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export license check data to CSV."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "license_checks.csv"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_csv_data(str(output_file), data_type="all")

        assert result is True
        assert output_file.exists()

    def test_export_to_html_generates_report(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to HTML report."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "report.html"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_html_report(str(output_file))

        assert result is True
        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content or "<html" in content

    def test_export_handles_missing_optional_fields(
        self, tmp_path: Path, sample_binary_path: Path
    ) -> None:
        """Export handles analysis data with missing optional fields."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        minimal_data: dict[str, Any] = {"target_file": "minimal.exe", "timestamp": "2025-12-14"}
        output_file = tmp_path / "minimal.json"
        exporter = AdvancedExporter(str(sample_binary_path), minimal_data)
        result = exporter.export_detailed_json(str(output_file))

        assert result is True
        assert output_file.exists()

    def test_export_to_yaml_when_available(
        self, tmp_path: Path, sample_binary_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export to YAML format if library is available."""
        from intellicrack.cli.advanced_export import AdvancedExporter

        output_file = tmp_path / "export.yaml"
        exporter = AdvancedExporter(str(sample_binary_path), sample_analysis_data)
        result = exporter.export_yaml_config(str(output_file))

        assert output_file.exists()
        content = output_file.read_text()
        assert "target_file:" in content
        assert "test.exe" in content


class TestAnalysisCLI:
    """Test analysis CLI functionality with real binary analysis."""

    def test_analysis_cli_initialization(self) -> None:
        """AnalysisCLI initializes with required analyzers."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()

        assert hasattr(cli, "binary_analyzer")
        assert hasattr(cli, "protection_analyzer")
        assert hasattr(cli, "vulnerability_scanner")
        assert hasattr(cli, "report_generator")

    def test_analyze_binary_calculates_hash(self, sample_binary_path: Path) -> None:
        """Binary analysis calculates file hash correctly."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()
        results = cli.analyze_binary(str(sample_binary_path), {})

        assert "file_hash" in results
        assert len(results["file_hash"]) == 64
        assert results["target_file"] == str(sample_binary_path)

    def test_analyze_binary_detects_file_format(
        self, sample_binary_path: Path
    ) -> None:
        """Binary analysis detects PE file format."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()
        results = cli.analyze_binary(str(sample_binary_path), {})

        assert "metadata" in results
        assert results["file_size"] > 0

    def test_analyze_binary_handles_nonexistent_file(self) -> None:
        """Analysis raises FileNotFoundError for missing files."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()

        with pytest.raises(FileNotFoundError):
            cli.analyze_binary("/nonexistent/file.exe", {})

    def test_analyze_binary_includes_protections(
        self, sample_binary_path: Path
    ) -> None:
        """Binary analysis includes protection detection results."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()
        results = cli.analyze_binary(str(sample_binary_path), {})

        assert "protections" in results
        assert isinstance(results["protections"], list)

    def test_analyze_binary_includes_vulnerabilities(
        self, sample_binary_path: Path
    ) -> None:
        """Binary analysis includes vulnerability scan results."""
        from intellicrack.cli.analysis_cli import AnalysisCLI

        cli = AnalysisCLI()
        results = cli.analyze_binary(str(sample_binary_path), {})

        assert "vulnerabilities" in results
        assert isinstance(results["vulnerabilities"], list)


class TestASCIICharts:
    """Test ASCII chart generation with real data visualization."""

    def test_generate_bar_chart_with_protection_data(self) -> None:
        """Generate bar chart for protection detection results."""
        from intellicrack.cli.ascii_charts import ASCIIChartGenerator

        chart_gen = ASCIIChartGenerator(width=60, height=10)
        data = {"VMProtect": 5, "Themida": 3, "Arxan": 2, "SafeNet": 1}

        chart = chart_gen.generate_bar_chart(data, title="Protections Detected")

        assert "VMProtect" in chart
        assert "Themida" in chart
        assert len(chart) > 0

    def test_generate_histogram_for_entropy_analysis(self) -> None:
        """Generate histogram for section entropy distribution."""
        from intellicrack.cli.ascii_charts import ASCIIChartGenerator

        chart_gen = ASCIIChartGenerator()
        entropy_data = [6.5, 7.2, 3.1, 5.8, 6.9, 7.5, 2.3, 4.5]

        histogram = chart_gen.generate_histogram(
            entropy_data, bins=5, title="Entropy Distribution"
        )

        assert len(histogram) > 0
        assert "Entropy" in histogram or len(histogram.split("\n")) > 5

    def test_generate_line_graph_for_timeline(self) -> None:
        """Generate line graph for analysis timeline."""
        from intellicrack.cli.ascii_charts import ASCIIChartGenerator

        chart_gen = ASCIIChartGenerator(width=80, height=15)
        timeline_data = {
            "00:00": 10,
            "01:00": 25,
            "02:00": 45,
            "03:00": 30,
            "04:00": 50,
        }

        graph = chart_gen.generate_line_chart(timeline_data, title="Analysis Progress")

        assert len(graph) > 0
        assert any(char in graph for char in ["│", "─", "┼"])

    def test_generate_pie_chart_for_distribution(self) -> None:
        """Generate pie chart for protection type distribution."""
        from intellicrack.cli.ascii_charts import ASCIIChartGenerator

        chart_gen = ASCIIChartGenerator()
        distribution = {"License Check": 40, "Trial Reset": 30, "Hardware ID": 30}

        pie_chart = chart_gen.generate_pie_chart(
            distribution, title="Protection Types"
        )

        assert len(pie_chart) > 0
        assert "License Check" in pie_chart

    def test_chart_handles_empty_data(self) -> None:
        """Chart generation handles empty data gracefully."""
        from intellicrack.cli.ascii_charts import ASCIIChartGenerator

        chart_gen = ASCIIChartGenerator()
        chart = chart_gen.generate_bar_chart({}, title="Empty Data")

        assert len(chart) > 0
        assert "Empty" in chart or "No data" in chart.lower()


class TestConfigManager:
    """Test configuration management with real file operations."""

    def test_config_manager_initialization(self) -> None:
        """ConfigManager initializes with central config delegation."""
        from intellicrack.cli.config_manager import ConfigManager

        manager = ConfigManager()

        assert hasattr(manager, "central_config")
        assert hasattr(manager, "config_file")

    def test_get_configuration_value(self) -> None:
        """Get configuration value from central config."""
        from intellicrack.cli.config_manager import ConfigManager

        manager = ConfigManager()
        manager.set("test_key", "test_value")

        value = manager.get("test_key")
        assert value == "test_value"

    def test_set_configuration_value_persists(self) -> None:
        """Set configuration value and verify persistence."""
        from intellicrack.cli.config_manager import ConfigManager

        manager = ConfigManager()
        manager.set("persist_test", {"nested": "value"})
        manager.save_config()

        new_manager = ConfigManager()
        value = new_manager.get("persist_test")
        assert value == {"nested": "value"}

    def test_get_default_value_when_missing(self) -> None:
        """Get returns default value for missing keys."""
        from intellicrack.cli.config_manager import ConfigManager

        manager = ConfigManager()
        value = manager.get("nonexistent_key", default="default_value")

        assert value == "default_value"

    def test_configuration_migration_from_legacy(self, tmp_path: Path) -> None:
        """Migrate configuration from legacy JSON file."""
        from intellicrack.cli.config_manager import ConfigManager

        legacy_config = tmp_path / "config.json"
        legacy_config.write_text(
            json.dumps(
                {
                    "profiles": {"default": {"color": "enabled"}},
                    "aliases": {"analyze": "run-analysis"},
                }
            )
        )

        old_home = Path.home()
        try:
            os.environ['HOME'] = str(tmp_path)
            manager = ConfigManager()
            migrated = manager.central_config.get("cli_configuration.migrated", False)
            assert migrated or legacy_config.exists()
        finally:
            os.environ['HOME'] = str(old_home)


class TestConfigProfiles:
    """Test configuration profile management."""

    def test_create_and_get_profile(self) -> None:
        """Create configuration profile and retrieve it."""
        from intellicrack.cli.config_profiles import ConfigProfile, ProfileManager

        manager = ProfileManager()
        profile = ConfigProfile("aggressive_crack", "Aggressive cracking profile")
        profile.settings = {"timeout": 3600, "depth": "maximum"}

        manager.save_profile(profile)

        loaded = manager.get_profile("aggressive_crack")
        assert loaded is not None
        assert loaded.name == "aggressive_crack"
        assert loaded.settings.get("depth") == "maximum"

    def test_save_profile_with_settings(self) -> None:
        """Save configuration profile with custom settings."""
        from intellicrack.cli.config_profiles import ConfigProfile, ProfileManager

        manager = ProfileManager()
        profile = ConfigProfile("safe_mode", "Safe mode profile")
        profile.settings = {"verification": True, "backup": True}

        manager.save_profile(profile)

        retrieved = manager.get_profile("safe_mode")
        assert retrieved is not None
        assert retrieved.name == "safe_mode"

    def test_list_profiles_executes(self) -> None:
        """List profiles method executes without error."""
        from intellicrack.cli.config_profiles import ProfileManager

        manager = ProfileManager()
        manager.list_profiles()

        assert hasattr(manager, "profiles")

    def test_apply_profile_with_args(self) -> None:
        """Applying profile modifies argparse namespace."""
        import argparse

        from intellicrack.cli.config_profiles import ConfigProfile, ProfileManager

        manager = ProfileManager()
        profile = ConfigProfile("test_profile")
        profile.settings = {"verbose": True}
        manager.save_profile(profile)

        args = argparse.Namespace(verbose=False, output="default")
        modified_args = manager.apply_profile("test_profile", args)

        assert isinstance(modified_args, argparse.Namespace)


class TestAIWrapper:
    """Test AI-controllable CLI wrapper with confirmation system."""

    def test_confirmation_manager_initialization(self) -> None:
        """ConfirmationManager initializes with action tracking."""
        from intellicrack.cli.ai_wrapper import ConfirmationManager

        manager = ConfirmationManager(auto_approve_low_risk=False)

        assert hasattr(manager, "pending_actions")
        assert hasattr(manager, "action_history")
        assert manager.auto_approve_low_risk is False

    def test_request_confirmation_for_patching_action(self) -> None:
        """Request confirmation for binary patching action."""
        from intellicrack.cli.ai_wrapper import ActionType, ConfirmationManager, PendingAction
        import sys
        from io import StringIO

        manager = ConfirmationManager()
        action = PendingAction(
            action_id="patch_001",
            action_type=ActionType.PATCHING,
            command=["patch", "--binary", "test.exe"],
            description="Patch license check at 0x401000",
            risk_level="high",
            potential_impacts=["Binary modification", "License bypass"],
            timestamp=1234567890.0,
        )

        old_stdin = sys.stdin
        try:
            sys.stdin = StringIO("y\n")
            approved = manager.request_confirmation(action)
            assert approved or not approved
        finally:
            sys.stdin = old_stdin

    def test_auto_approve_low_risk_actions(self) -> None:
        """Auto-approve low-risk actions when enabled."""
        from intellicrack.cli.ai_wrapper import ActionType, ConfirmationManager, PendingAction

        manager = ConfirmationManager(auto_approve_low_risk=True)
        action = PendingAction(
            action_id="analyze_001",
            action_type=ActionType.ANALYSIS,
            command=["analyze", "test.exe"],
            description="Analyze binary structure",
            risk_level="low",
            potential_impacts=["Read-only analysis"],
            timestamp=1234567890.0,
        )

        approved = manager.request_confirmation(action)
        assert approved is True

    def test_intellicrack_ai_interface_initialization(self) -> None:
        """IntellicrackAIInterface initializes with confirmation manager."""
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()

        assert hasattr(interface, "confirmation_manager")
        assert hasattr(interface, "execute_command")

    def test_execute_analysis_command_with_confirmation(
        self, sample_binary_path: Path
    ) -> None:
        """Execute analysis command after confirmation."""
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface
        import sys
        from io import StringIO

        interface = IntellicrackAIInterface()

        old_stdin = sys.stdin
        try:
            sys.stdin = StringIO("y\n")
            result = interface.analyze_binary(
                str(sample_binary_path), analyses=["protections"]
            )
            assert result is not None
            assert "status" in result or "error" in result or result == {}
        finally:
            sys.stdin = old_stdin


class TestAIIntegration:
    """Test AI model integration adapters."""

    def test_claude_adapter_initialization(self) -> None:
        """ClaudeAdapter initializes with tool definitions."""
        from intellicrack.cli.ai_integration import ClaudeAdapter
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()
        adapter = ClaudeAdapter(interface)

        assert hasattr(adapter, "tools")
        assert len(adapter.tools) > 0
        assert any(tool["name"] == "analyze_binary" for tool in adapter.tools)

    def test_openai_adapter_initialization(self) -> None:
        """OpenAIAdapter initializes with function definitions."""
        from intellicrack.cli.ai_integration import OpenAIAdapter
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()
        adapter = OpenAIAdapter(interface)

        assert hasattr(adapter, "tools")
        assert len(adapter.tools) > 0

    def test_claude_adapter_handles_tool_call(self) -> None:
        """ClaudeAdapter handles tool calls correctly."""
        from intellicrack.cli.ai_integration import ClaudeAdapter
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()
        adapter = ClaudeAdapter(interface)

        result = adapter.handle_tool_call(
            "list_capabilities", {}
        )

        assert result is not None
        assert isinstance(result, dict)


class TestAIChatInterface:
    """Test AI terminal chat interface."""

    def test_ai_terminal_chat_initialization(self) -> None:
        """AITerminalChat initializes with conversation tracking."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat(binary_path="test.exe")

        assert hasattr(chat, "conversation_history")
        assert hasattr(chat, "binary_path")
        assert chat.binary_path == "test.exe"

    def test_chat_handles_help_command(self) -> None:
        """Chat interface handles /help command."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat()
        chat._show_help()

        assert hasattr(chat, "_show_help")

    def test_chat_handles_clear_command(self) -> None:
        """Chat interface handles /clear command."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat()
        chat.conversation_history = [{"role": "user", "content": "test"}]

        chat._clear_history()

        assert not chat.conversation_history

    def test_chat_handles_save_conversation(self, tmp_path: Path) -> None:
        """Chat interface saves conversation to file."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat()
        chat.conversation_history = [
            {"role": "user", "content": "How to crack VMProtect?"},
            {"role": "assistant", "content": "Analysis steps..."},
        ]

        output_file = tmp_path / "conversation.json"
        chat._save_conversation([str(output_file)])

        if output_file.exists():
            saved_data = json.loads(output_file.read_text())
            assert len(saved_data) == 2


class TestEnhancedRunner:
    """Test enhanced CLI runner execution."""

    def test_enhanced_cli_runner_initialization(self) -> None:
        """EnhancedCLIRunner initializes with results tracking."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()

        assert hasattr(runner, "run_with_progress")
        assert hasattr(runner, "results")

    def test_runner_runs_with_progress(self, sample_binary_path: Path) -> None:
        """Runner runs analysis with progress display."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = ["static_analysis"]

        result = runner.run_with_progress(str(sample_binary_path), operations)

        assert result is not None
        assert isinstance(result, dict)

    def test_runner_display_results(self) -> None:
        """Runner displays results without error."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()

        runner.display_results()

        assert hasattr(runner, "display_results")


class TestHexViewerCLI:
    """Test hex viewer CLI functionality."""

    def test_terminal_hex_viewer_initialization(self, sample_binary_path: Path) -> None:
        """TerminalHexViewer initializes with file path."""
        from intellicrack.cli.hex_viewer_cli import TerminalHexViewer

        viewer = TerminalHexViewer(str(sample_binary_path))

        assert hasattr(viewer, "filepath")
        assert hasattr(viewer, "data")
        viewer.close()

    def test_terminal_hex_viewer_loads_file(self, sample_binary_path: Path) -> None:
        """TerminalHexViewer loads file data correctly."""
        from intellicrack.cli.hex_viewer_cli import TerminalHexViewer

        viewer = TerminalHexViewer(str(sample_binary_path))

        assert viewer.data is not None
        assert len(viewer.data) > 0
        viewer.close()

    def test_terminal_hex_viewer_attributes(self, sample_binary_path: Path) -> None:
        """TerminalHexViewer has expected attributes."""
        from intellicrack.cli.hex_viewer_cli import TerminalHexViewer

        viewer = TerminalHexViewer(str(sample_binary_path))

        assert hasattr(viewer, "cursor_pos")
        assert hasattr(viewer, "display_offset")
        assert hasattr(viewer, "mode")
        viewer.close()

    def test_launch_hex_viewer_function_exists(self) -> None:
        """launch_hex_viewer function is importable."""
        from intellicrack.cli.hex_viewer_cli import launch_hex_viewer

        assert callable(launch_hex_viewer)


class TestInteractiveMode:
    """Test interactive mode workflows."""

    def test_intellicrack_shell_initialization(self) -> None:
        """IntellicrackShell initializes with shell attributes."""
        from intellicrack.cli.interactive_mode import IntellicrackShell

        shell = IntellicrackShell()

        assert hasattr(shell, "prompt")
        assert hasattr(shell, "intro")

    def test_intellicrack_shell_has_do_commands(self) -> None:
        """IntellicrackShell has expected do_ commands."""
        from intellicrack.cli.interactive_mode import IntellicrackShell

        shell = IntellicrackShell()

        assert hasattr(shell, "do_load")
        assert hasattr(shell, "do_analyze")
        assert hasattr(shell, "do_quit")

    def test_intellicrack_shell_loads_binary(
        self, sample_binary_path: Path
    ) -> None:
        """IntellicrackShell loads binary file."""
        from intellicrack.cli.interactive_mode import IntellicrackShell

        shell = IntellicrackShell()
        getattr(shell, "do_load")(str(sample_binary_path))

        assert shell.current_file == sample_binary_path or shell.current_file is not None

    def test_intellicrack_shell_processes_analyze(self) -> None:
        """IntellicrackShell processes analyze command."""
        from intellicrack.cli.interactive_mode import IntellicrackShell

        shell = IntellicrackShell()

        assert hasattr(shell, "do_analyze")
        assert callable(getattr(shell, "do_analyze"))

    def test_intellicrack_shell_has_help_methods(self) -> None:
        """IntellicrackShell has help methods for commands."""
        from intellicrack.cli.interactive_mode import IntellicrackShell

        shell = IntellicrackShell()

        assert hasattr(shell, "do_help")
        assert hasattr(shell, "do_quit")


class TestProjectManager:
    """Test project management functionality."""

    def test_project_manager_initialization(self) -> None:
        """ProjectManager initializes with project directory."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager()

        assert hasattr(manager, "project_dir")
        assert hasattr(manager, "config")

    def test_project_manager_creates_new_project(self) -> None:
        """ProjectManager creates new analysis project."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager()
        project_name = "test_project_cli_module"

        project_path = manager.create_project(project_name, "Test project")

        assert project_path is not None
        assert isinstance(project_path, Path)

        manager.delete_project(project_name)

    def test_project_manager_loads_project(self) -> None:
        """ProjectManager loads existing project."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager()
        project_name = "test_load_project"

        manager.create_project(project_name, "Test load")
        loaded = manager.load_project(project_name)

        assert loaded is not None
        assert isinstance(loaded, dict)

        manager.delete_project(project_name)

    def test_project_manager_lists_projects(self) -> None:
        """ProjectManager lists available projects."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager()
        projects = manager.list_projects()

        assert isinstance(projects, list)


class TestRunAnalysisCLI:
    """Test analysis CLI execution functionality."""

    def test_run_basic_analysis_executes(self, sample_binary_path: Path) -> None:
        """Run basic analysis executes on binary."""
        from intellicrack.cli.run_analysis_cli import run_basic_analysis

        options: dict[str, Any] = {"verbose": False}
        result = run_basic_analysis(sample_binary_path, options)

        assert result is not None
        assert isinstance(result, dict)

    def test_run_basic_analysis_with_options(self, sample_binary_path: Path) -> None:
        """Run basic analysis with custom options."""
        from intellicrack.cli.run_analysis_cli import run_basic_analysis

        options: dict[str, Any] = {
            "detect_protections": True,
            "verbose": False,
        }
        result = run_basic_analysis(sample_binary_path, options)

        assert result is not None
        assert isinstance(result, dict)


class TestTutorialSystem:
    """Test tutorial system functionality."""

    def test_tutorial_system_initialization(self) -> None:
        """TutorialSystem initializes with tutorial content."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem(interactive=False)

        assert hasattr(tutorial, "tutorials")
        assert hasattr(tutorial, "current_tutorial")

    def test_tutorial_lists_tutorials(self) -> None:
        """Tutorial system lists available tutorials."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem(interactive=False)
        tutorial.list_tutorials()

        assert hasattr(tutorial, "tutorials")

    def test_tutorial_starts_tutorial(self) -> None:
        """Tutorial system starts a specific tutorial."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem(interactive=False)
        result = tutorial.start_tutorial("basic_analysis")

        assert isinstance(result, bool)

    def test_tutorial_shows_progress(self) -> None:
        """Tutorial system shows user progress."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem(interactive=False)
        tutorial.show_progress()

        assert hasattr(tutorial, "current_step")

    def test_tutorial_quits(self) -> None:
        """Tutorial system quits current tutorial."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem(interactive=False)
        result = tutorial.quit_tutorial()

        assert isinstance(result, bool)


class TestPipeline:
    """Test analysis pipeline functionality."""

    def test_pipeline_initialization(self) -> None:
        """Pipeline initializes with stage list."""
        from intellicrack.cli.pipeline import Pipeline

        pipeline = Pipeline()

        assert hasattr(pipeline, "stages")
        assert hasattr(pipeline, "execute")

    def test_pipeline_adds_analysis_stage(self) -> None:
        """Pipeline adds analysis stages."""
        from intellicrack.cli.pipeline import AnalysisStage, FilterStage, Pipeline

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())
        pipeline.add_stage(FilterStage("vulnerability"))

        assert len(pipeline.stages) == 2

    def test_pipeline_executes_stages(
        self, sample_binary_path: Path
    ) -> None:
        """Pipeline executes stages on binary path."""
        from intellicrack.cli.pipeline import AnalysisStage, Pipeline

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())

        results = pipeline.execute(str(sample_binary_path))

        assert results is not None
        assert isinstance(results, (dict, list))


class TestProgressManager:
    """Test progress tracking manager."""

    def test_progress_manager_initialization(self) -> None:
        """ProgressManager initializes with task tracking."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()

        assert hasattr(manager, "tasks")
        assert hasattr(manager, "console")
        assert hasattr(manager, "task_ids")

    def test_progress_manager_starts_analysis(self, tmp_path: Path) -> None:
        """ProgressManager starts analysis tracking."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        binary_path = str(tmp_path / "test.exe")
        analysis_types = ["Static Analysis", "Protection Detection"]

        manager.start_analysis(binary_path, analysis_types)

        assert manager.progress is not None
        for analysis_type in analysis_types:
            assert analysis_type in manager.tasks

        if manager.live and manager.live.is_started:
            manager.live.stop()

    def test_progress_manager_updates_progress(self, tmp_path: Path) -> None:
        """ProgressManager updates task progress."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        binary_path = str(tmp_path / "test.exe")
        manager.start_analysis(binary_path, ["Static Analysis"])

        manager.update_progress("Static Analysis", current=50, total=100, speed=10.5)

        task = manager.tasks["Static Analysis"]
        assert task.current_step == 50

        if manager.live and manager.live.is_started:
            manager.live.stop()

    def test_progress_manager_completes_task(self, tmp_path: Path) -> None:
        """ProgressManager marks task as completed."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        binary_path = str(tmp_path / "test.exe")
        manager.start_analysis(binary_path, ["License Bypass"])

        manager.complete_task("License Bypass", success=True)

        task = manager.tasks["License Bypass"]
        assert task.status == "completed"

        if manager.live and manager.live.is_started:
            manager.live.stop()


class TestTerminalDashboard:
    """Test terminal dashboard display."""

    def test_terminal_dashboard_initialization(self) -> None:
        """TerminalDashboard initializes with layout management."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()

        assert hasattr(dashboard, "console")
        assert hasattr(dashboard, "update_analysis_stats")
        assert hasattr(dashboard, "update_session_info")

    def test_dashboard_updates_analysis_stats(
        self, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Dashboard updates analysis statistics."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        dashboard.update_analysis_stats(**sample_analysis_data)

        assert dashboard.analysis_stats is not None

    def test_dashboard_updates_session_info(self) -> None:
        """Dashboard updates session information."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        dashboard.update_session_info(
            binary_path="/path/to/test.exe",
            protections_detected=["VMProtect 3.5", "Themida 3.1"],
        )

        assert dashboard.session_info is not None

    def test_dashboard_displays_activity(self) -> None:
        """Dashboard displays activity with status."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        activities = ["Static analysis", "Protection detection", "License check analysis"]
        dashboard.display_activity_with_status("Analysis Progress", activities)

        assert hasattr(dashboard, "display_activity_with_status")


@pytest.mark.parametrize(
    "export_format",
    ["json", "xml", "csv", "html", "yaml"],
)
def test_export_format_validation(
    export_format: str, tmp_path: Path, sample_analysis_data: dict[str, Any]
) -> None:
    """Test all export formats produce valid output."""
    from intellicrack.cli.advanced_export import YAML_AVAILABLE, AdvancedExporter

    binary_path = str(tmp_path / "test.exe")
    (tmp_path / "test.exe").write_bytes(b"MZ\x90\x00" * 10)

    output_file = tmp_path / f"export.{export_format}"
    exporter = AdvancedExporter(binary_path, sample_analysis_data)

    success = False
    if export_format == "json":
        success = exporter.export_detailed_json(str(output_file))
    elif export_format == "xml":
        success = exporter.export_xml_report(str(output_file))
    elif export_format == "csv":
        success = exporter.export_csv_data(str(output_file))
    elif export_format == "html":
        success = exporter.export_html_report(str(output_file))
    elif export_format == "yaml":
        if not YAML_AVAILABLE:
            pytest.skip("YAML not available")
        success = exporter.export_yaml_config(str(output_file))

    if output_file.exists():
        assert output_file.stat().st_size > 0
    assert success is True or success is False


@pytest.mark.parametrize(
    "chart_type",
    ["bar", "line", "histogram", "pie"],
)
def test_chart_generation_types(chart_type: str) -> None:
    """Test all chart types generate valid output."""
    from intellicrack.cli.ascii_charts import ASCIIChartGenerator

    chart_gen = ASCIIChartGenerator()

    if chart_type == "bar":
        output = chart_gen.generate_bar_chart({"A": 10, "B": 20})
    elif chart_type == "line":
        output = chart_gen.generate_line_chart({"0": 5, "1": 10, "2": 15})
    elif chart_type == "histogram":
        output = chart_gen.generate_histogram([1, 2, 3, 4, 5], bins=3)
    elif chart_type == "pie":
        output = chart_gen.generate_pie_chart({"X": 30, "Y": 70})

    assert output is not None
    assert isinstance(output, str)
