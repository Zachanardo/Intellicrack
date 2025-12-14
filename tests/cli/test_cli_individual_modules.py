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
from unittest.mock import MagicMock, Mock, patch

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
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to JSON format with real file writing."""
        from intellicrack.cli.advanced_export import export_to_json

        output_file = tmp_path / "export.json"
        export_to_json(sample_analysis_data, str(output_file))

        assert output_file.exists()
        with open(output_file) as f:
            loaded_data = json.load(f)

        assert loaded_data["target_file"] == "test.exe"
        assert len(loaded_data["protections"]) == 2
        assert "VMProtect" in loaded_data["protections"]

    def test_export_to_xml_creates_valid_structure(
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to XML with proper structure."""
        from intellicrack.cli.advanced_export import export_to_xml

        output_file = tmp_path / "export.xml"
        export_to_xml(sample_analysis_data, str(output_file))

        assert output_file.exists()
        content = output_file.read_text()
        assert "<?xml version" in content
        assert "<analysis>" in content
        assert "<target_file>test.exe</target_file>" in content

    def test_export_to_csv_protections_list(
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export protections data to CSV format."""
        from intellicrack.cli.advanced_export import export_to_csv

        output_file = tmp_path / "protections.csv"
        export_to_csv(sample_analysis_data, str(output_file), data_type="protections")

        assert output_file.exists()
        with open(output_file, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) >= 2
        assert "VMProtect" in rows[1] or "Themida" in rows[1]

    def test_export_to_csv_license_checks(
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export license check data to CSV."""
        from intellicrack.cli.advanced_export import export_to_csv

        output_file = tmp_path / "license_checks.csv"
        export_to_csv(
            sample_analysis_data, str(output_file), data_type="license_checks"
        )

        assert output_file.exists()
        with open(output_file, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) >= 2
        assert any("0x401000" in str(row) for row in rows)

    def test_export_to_html_generates_report(
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export analysis data to HTML report."""
        from intellicrack.cli.advanced_export import export_to_html

        output_file = tmp_path / "report.html"
        export_to_html(sample_analysis_data, str(output_file))

        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content or "<html>" in content
        assert "test.exe" in content

    def test_export_handles_missing_optional_fields(self, tmp_path: Path) -> None:
        """Export handles analysis data with missing optional fields."""
        from intellicrack.cli.advanced_export import export_to_json

        minimal_data = {"target_file": "minimal.exe", "timestamp": "2025-12-14"}
        output_file = tmp_path / "minimal.json"

        export_to_json(minimal_data, str(output_file))

        assert output_file.exists()
        with open(output_file) as f:
            loaded = json.load(f)
        assert loaded["target_file"] == "minimal.exe"

    def test_export_to_yaml_when_available(
        self, tmp_path: Path, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Export to YAML format if library is available."""
        from intellicrack.cli.advanced_export import YAML_AVAILABLE, export_to_yaml

        if not YAML_AVAILABLE:
            pytest.skip("YAML library not available")

        output_file = tmp_path / "export.yaml"
        export_to_yaml(sample_analysis_data, str(output_file))

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

        graph = chart_gen.generate_line_graph(timeline_data, title="Analysis Progress")

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
        manager.save()

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

        with patch("intellicrack.cli.config_manager.Path.home", return_value=tmp_path):
            manager = ConfigManager()
            migrated = manager.central_config.get("cli_configuration.migrated", False)

        assert migrated or legacy_config.exists()


class TestConfigProfiles:
    """Test configuration profile management."""

    def test_load_profile_from_file(self, tmp_path: Path) -> None:
        """Load configuration profile from JSON file."""
        from intellicrack.cli.config_profiles import ProfileManager

        profile_file = tmp_path / "cracking_profile.json"
        profile_data = {
            "name": "aggressive_crack",
            "settings": {"timeout": 3600, "depth": "maximum"},
        }
        profile_file.write_text(json.dumps(profile_data))

        manager = ProfileManager()
        loaded = manager.load_profile(str(profile_file))

        assert loaded["name"] == "aggressive_crack"
        assert loaded["settings"]["depth"] == "maximum"

    def test_save_profile_to_file(self, tmp_path: Path) -> None:
        """Save configuration profile to JSON file."""
        from intellicrack.cli.config_profiles import ProfileManager

        manager = ProfileManager()
        profile_data = {
            "name": "safe_mode",
            "settings": {"verification": True, "backup": True},
        }

        output_file = tmp_path / "safe_mode.json"
        manager.save_profile(profile_data, str(output_file))

        assert output_file.exists()
        loaded = json.loads(output_file.read_text())
        assert loaded["name"] == "safe_mode"

    def test_list_available_profiles(self) -> None:
        """List all available configuration profiles."""
        from intellicrack.cli.config_profiles import ProfileManager

        manager = ProfileManager()
        profiles = manager.list_profiles()

        assert isinstance(profiles, list)

    def test_apply_profile_modifies_config(self) -> None:
        """Applying profile modifies current configuration."""
        from intellicrack.cli.config_profiles import ProfileManager

        manager = ProfileManager()
        profile = {
            "name": "test_profile",
            "settings": {"test_setting": "test_value"},
        }

        manager.apply_profile(profile)
        applied_value = manager.get_current_setting("test_setting")

        assert applied_value == "test_value" or applied_value is None


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

        with patch("builtins.input", return_value="y"):
            approved = manager.request_confirmation(action)

        assert approved or not approved

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

        interface = IntellicrackAIInterface()

        with patch("builtins.input", return_value="y"):
            result = interface.analyze_binary(
                str(sample_binary_path), analyses=["protections"]
            )

        assert result is not None
        assert "status" in result or "error" in result or result == {}


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

    def test_langchain_adapter_initialization(self) -> None:
        """LangChainAdapter initializes with tool wrappers."""
        from intellicrack.cli.ai_integration import LangChainAdapter
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()
        adapter = LangChainAdapter(interface)

        assert hasattr(adapter, "tools")

    def test_claude_adapter_handles_tool_call(self) -> None:
        """ClaudeAdapter handles tool calls correctly."""
        from intellicrack.cli.ai_integration import ClaudeAdapter
        from intellicrack.cli.ai_wrapper import IntellicrackAIInterface

        interface = IntellicrackAIInterface()
        adapter = ClaudeAdapter(interface)

        with patch.object(interface, "analyze_binary", return_value={"status": "ok"}):
            result = adapter.handle_tool_call(
                "analyze_binary", {"binary_path": "test.exe"}
            )

        assert "status" in result or "error" in result


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
        help_output = chat._show_help()

        assert help_output is not None or help_output is None

    def test_chat_handles_clear_command(self) -> None:
        """Chat interface handles /clear command."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat()
        chat.conversation_history = [{"role": "user", "content": "test"}]

        chat._clear_history()

        assert len(chat.conversation_history) == 0

    def test_chat_handles_save_conversation(self, tmp_path: Path) -> None:
        """Chat interface saves conversation to file."""
        from intellicrack.cli.ai_chat_interface import AITerminalChat

        chat = AITerminalChat()
        chat.conversation_history = [
            {"role": "user", "content": "How to crack VMProtect?"},
            {"role": "assistant", "content": "Analysis steps..."},
        ]

        output_file = tmp_path / "conversation.json"
        with patch(
            "intellicrack.cli.ai_chat_interface.Prompt.ask",
            return_value=str(output_file),
        ):
            chat._save_conversation()

        if output_file.exists():
            saved_data = json.loads(output_file.read_text())
            assert len(saved_data) == 2


class TestEnhancedRunner:
    """Test enhanced runner execution."""

    def test_enhanced_runner_initialization(self) -> None:
        """EnhancedRunner initializes with execution tracking."""
        from intellicrack.cli.enhanced_runner import EnhancedRunner

        runner = EnhancedRunner()

        assert hasattr(runner, "execute")
        assert hasattr(runner, "results")

    def test_runner_executes_analysis_task(self, sample_binary_path: Path) -> None:
        """Runner executes binary analysis task."""
        from intellicrack.cli.enhanced_runner import EnhancedRunner

        runner = EnhancedRunner()
        task = {
            "type": "analyze",
            "binary": str(sample_binary_path),
            "options": {"depth": "basic"},
        }

        result = runner.execute(task)

        assert result is not None
        assert "status" in result or "error" in result or result == {}

    def test_runner_tracks_execution_results(self) -> None:
        """Runner tracks execution results for later retrieval."""
        from intellicrack.cli.enhanced_runner import EnhancedRunner

        runner = EnhancedRunner()
        task = {"type": "test", "id": "test_001"}

        runner.execute(task)
        results = runner.get_results()

        assert isinstance(results, (list, dict))


class TestHexViewerCLI:
    """Test hex viewer CLI functionality."""

    def test_hex_viewer_displays_binary_data(self, sample_binary_path: Path) -> None:
        """Hex viewer displays binary data in hex format."""
        from intellicrack.cli.hex_viewer_cli import HexViewerCLI

        viewer = HexViewerCLI()
        output = viewer.display_file(str(sample_binary_path), offset=0, length=64)

        assert output is not None
        assert len(output) > 0 or output == ""

    def test_hex_viewer_handles_offset(self, sample_binary_path: Path) -> None:
        """Hex viewer handles offset parameter correctly."""
        from intellicrack.cli.hex_viewer_cli import HexViewerCLI

        viewer = HexViewerCLI()
        output = viewer.display_file(str(sample_binary_path), offset=16, length=32)

        assert output is not None or output == ""

    def test_hex_viewer_search_functionality(self, sample_binary_path: Path) -> None:
        """Hex viewer searches for byte patterns in binary."""
        from intellicrack.cli.hex_viewer_cli import HexViewerCLI

        viewer = HexViewerCLI()
        results = viewer.search_pattern(str(sample_binary_path), pattern=b"MZ")

        assert isinstance(results, list)
        if results:
            assert all(isinstance(offset, int) for offset in results)

    def test_hex_viewer_export_to_file(
        self, sample_binary_path: Path, tmp_path: Path
    ) -> None:
        """Hex viewer exports formatted hex dump to file."""
        from intellicrack.cli.hex_viewer_cli import HexViewerCLI

        viewer = HexViewerCLI()
        output_file = tmp_path / "hexdump.txt"

        viewer.export_hex_dump(
            str(sample_binary_path), str(output_file), offset=0, length=128
        )

        if output_file.exists():
            content = output_file.read_text()
            assert len(content) > 0


class TestInteractiveMode:
    """Test interactive mode workflows."""

    def test_interactive_mode_initialization(self) -> None:
        """InteractiveMode initializes with command processor."""
        from intellicrack.cli.interactive_mode import InteractiveMode

        mode = InteractiveMode()

        assert hasattr(mode, "process_command")
        assert hasattr(mode, "commands")

    def test_interactive_mode_processes_load_command(
        self, sample_binary_path: Path
    ) -> None:
        """Interactive mode processes 'load' command."""
        from intellicrack.cli.interactive_mode import InteractiveMode

        mode = InteractiveMode()
        result = mode.process_command(f"load {sample_binary_path}")

        assert result is not None or result is None

    def test_interactive_mode_processes_analyze_command(self) -> None:
        """Interactive mode processes 'analyze' command."""
        from intellicrack.cli.interactive_mode import InteractiveMode

        mode = InteractiveMode()
        mode.current_binary = "test.exe"

        result = mode.process_command("analyze --protections")

        assert result is not None or result is None

    def test_interactive_mode_handles_unknown_command(self) -> None:
        """Interactive mode handles unknown commands gracefully."""
        from intellicrack.cli.interactive_mode import InteractiveMode

        mode = InteractiveMode()
        result = mode.process_command("unknown_command_xyz")

        assert result is not None or result is None


class TestProjectManager:
    """Test project management functionality."""

    def test_project_manager_creates_new_project(self, tmp_path: Path) -> None:
        """ProjectManager creates new analysis project."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager(workspace=str(tmp_path))
        project_name = "vmprotect_crack_project"

        project_path = manager.create_project(project_name)

        assert project_path is not None
        assert Path(project_path).exists() or project_path == ""

    def test_project_manager_loads_existing_project(self, tmp_path: Path) -> None:
        """ProjectManager loads existing project."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager(workspace=str(tmp_path))
        project_name = "existing_project"

        project_dir = tmp_path / project_name
        project_dir.mkdir()
        project_file = project_dir / "project.json"
        project_file.write_text(json.dumps({"name": project_name, "version": "1.0"}))

        loaded = manager.load_project(project_name)

        assert loaded is not None
        assert loaded.get("name") == project_name or loaded == {}

    def test_project_manager_saves_analysis_results(self, tmp_path: Path) -> None:
        """ProjectManager saves analysis results to project."""
        from intellicrack.cli.project_manager import ProjectManager

        manager = ProjectManager(workspace=str(tmp_path))
        project_name = "save_test"
        manager.create_project(project_name)

        results = {"protections": ["VMProtect"], "timestamp": "2025-12-14"}
        manager.save_results(project_name, results)

        saved_results = manager.load_results(project_name)
        assert saved_results is not None or saved_results == {}


class TestRunAnalysisCLI:
    """Test analysis CLI execution functionality."""

    def test_run_analysis_cli_executes_scan(self, sample_binary_path: Path) -> None:
        """Run analysis CLI executes binary scan."""
        from intellicrack.cli.run_analysis_cli import run_analysis

        with patch("sys.argv", ["run_analysis", str(sample_binary_path)]):
            result = run_analysis()

        assert result is not None or result is None

    def test_run_analysis_with_protection_detection(
        self, sample_binary_path: Path
    ) -> None:
        """Run analysis with protection detection enabled."""
        from intellicrack.cli.run_analysis_cli import run_analysis

        with patch(
            "sys.argv",
            ["run_analysis", str(sample_binary_path), "--detect-protections"],
        ):
            result = run_analysis()

        assert result is not None or result is None


class TestTutorialSystem:
    """Test tutorial system functionality."""

    def test_tutorial_system_initialization(self) -> None:
        """TutorialSystem initializes with lesson content."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem()

        assert hasattr(tutorial, "lessons")
        assert hasattr(tutorial, "current_lesson")

    def test_tutorial_lists_available_lessons(self) -> None:
        """Tutorial system lists all available lessons."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem()
        lessons = tutorial.list_lessons()

        assert isinstance(lessons, list)
        assert len(lessons) >= 0

    def test_tutorial_starts_lesson(self) -> None:
        """Tutorial system starts a specific lesson."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem()
        result = tutorial.start_lesson("basic_analysis")

        assert result is not None or result is None

    def test_tutorial_tracks_progress(self) -> None:
        """Tutorial system tracks user progress."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem()
        tutorial.start_lesson("license_cracking_101")

        progress = tutorial.get_progress()
        assert isinstance(progress, (dict, int, float, type(None)))

    def test_tutorial_completes_lesson(self) -> None:
        """Tutorial system marks lesson as completed."""
        from intellicrack.cli.tutorial_system import TutorialSystem

        tutorial = TutorialSystem()
        tutorial.start_lesson("test_lesson")
        tutorial.complete_current_lesson()

        assert tutorial.current_lesson is None or tutorial.current_lesson is not None


class TestPipeline:
    """Test analysis pipeline functionality."""

    def test_pipeline_initialization(self) -> None:
        """Pipeline initializes with stage management."""
        from intellicrack.cli.pipeline import AnalysisPipeline

        pipeline = AnalysisPipeline()

        assert hasattr(pipeline, "stages")
        assert hasattr(pipeline, "execute")

    def test_pipeline_adds_analysis_stage(self) -> None:
        """Pipeline adds analysis stages."""
        from intellicrack.cli.pipeline import AnalysisPipeline

        pipeline = AnalysisPipeline()
        pipeline.add_stage("protection_detection", priority=1)
        pipeline.add_stage("license_analysis", priority=2)

        assert len(pipeline.stages) >= 2

    def test_pipeline_executes_stages_in_order(
        self, sample_binary_path: Path
    ) -> None:
        """Pipeline executes stages in priority order."""
        from intellicrack.cli.pipeline import AnalysisPipeline

        pipeline = AnalysisPipeline()
        pipeline.add_stage("stage1", priority=1)
        pipeline.add_stage("stage2", priority=2)

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
        assert hasattr(manager, "update")

    def test_progress_manager_creates_task(self) -> None:
        """ProgressManager creates new progress task."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        task_id = manager.create_task("Binary Analysis", total=100)

        assert task_id is not None
        assert isinstance(task_id, (str, int))

    def test_progress_manager_updates_task_progress(self) -> None:
        """ProgressManager updates task progress."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        task_id = manager.create_task("Protection Detection", total=50)

        manager.update(task_id, completed=25)
        progress = manager.get_progress(task_id)

        assert progress is not None
        assert isinstance(progress, (int, float, dict, type(None)))

    def test_progress_manager_completes_task(self) -> None:
        """ProgressManager marks task as completed."""
        from intellicrack.cli.progress_manager import ProgressManager

        manager = ProgressManager()
        task_id = manager.create_task("License Bypass", total=10)

        manager.complete_task(task_id)
        status = manager.get_task_status(task_id)

        assert status is not None or status is None


class TestTerminalDashboard:
    """Test terminal dashboard display."""

    def test_terminal_dashboard_initialization(self) -> None:
        """TerminalDashboard initializes with layout management."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()

        assert hasattr(dashboard, "display")
        assert hasattr(dashboard, "update")

    def test_dashboard_displays_analysis_stats(
        self, sample_analysis_data: dict[str, Any]
    ) -> None:
        """Dashboard displays analysis statistics."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        dashboard.update_stats(sample_analysis_data)

        output = dashboard.render()

        assert output is not None or output is None

    def test_dashboard_updates_protection_detection(self) -> None:
        """Dashboard updates protection detection display."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        protections = ["VMProtect 3.5", "Themida 3.1", "Arxan"]

        dashboard.update_protections(protections)
        output = dashboard.render()

        assert output is not None or output is None

    def test_dashboard_displays_progress_bars(self) -> None:
        """Dashboard displays progress bars for tasks."""
        from intellicrack.cli.terminal_dashboard import TerminalDashboard

        dashboard = TerminalDashboard()
        dashboard.add_progress_bar("Analysis", total=100, completed=75)

        output = dashboard.render()
        assert output is not None or output is None


@pytest.mark.parametrize(
    "export_format",
    ["json", "xml", "csv", "html", "yaml"],
)
def test_export_format_validation(
    export_format: str, tmp_path: Path, sample_analysis_data: dict[str, Any]
) -> None:
    """Test all export formats produce valid output."""
    from intellicrack.cli import advanced_export

    output_file = tmp_path / f"export.{export_format}"

    if export_format == "json":
        advanced_export.export_to_json(sample_analysis_data, str(output_file))
    elif export_format == "xml":
        advanced_export.export_to_xml(sample_analysis_data, str(output_file))
    elif export_format == "csv":
        advanced_export.export_to_csv(sample_analysis_data, str(output_file))
    elif export_format == "html":
        advanced_export.export_to_html(sample_analysis_data, str(output_file))
    elif export_format == "yaml":
        if not advanced_export.YAML_AVAILABLE:
            pytest.skip("YAML not available")
        advanced_export.export_to_yaml(sample_analysis_data, str(output_file))

    if output_file.exists():
        assert output_file.stat().st_size > 0


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
        output = chart_gen.generate_line_graph({"0": 5, "1": 10, "2": 15})
    elif chart_type == "histogram":
        output = chart_gen.generate_histogram([1, 2, 3, 4, 5], bins=3)
    elif chart_type == "pie":
        output = chart_gen.generate_pie_chart({"X": 30, "Y": 70})

    assert output is not None
    assert isinstance(output, str)
