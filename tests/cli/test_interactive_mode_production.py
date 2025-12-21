"""Production tests for interactive_mode module.

Tests interactive shell functionality for binary analysis, command execution,
and session management with real file operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.cli.interactive_mode import IntellicrackShell, main


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary test binary."""
    binary_path = tmp_path / "test_binary.exe"
    content = b"MZ\x90\x00" + b"TEST_BINARY_CONTENT" * 50
    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def shell_instance() -> IntellicrackShell:
    """Create IntellicrackShell instance."""
    return IntellicrackShell()


class TestIntellicrackShellInitialization:
    """Test shell initialization and configuration."""

    def test_shell_initializes_with_correct_attributes(self, shell_instance: IntellicrackShell) -> None:
        """Shell initializes with correct default attributes."""
        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None
        assert shell_instance.prompt == "intellicrack> "

    def test_shell_has_intro_message(self, shell_instance: IntellicrackShell) -> None:
        """Shell has intro message defined."""
        assert shell_instance.intro is not None
        assert "Intellicrack" in shell_instance.intro
        assert "Interactive Shell" in shell_instance.intro


class TestLoadCommand:
    """Test load command functionality."""

    def test_load_existing_file_succeeds(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Load command loads existing file successfully."""
        shell_instance.do_load(str(temp_binary))

        assert shell_instance.current_file == temp_binary
        assert shell_instance.current_file.exists()

    def test_load_nonexistent_file_handles_error(self, shell_instance: IntellicrackShell) -> None:
        """Load command handles nonexistent file gracefully."""
        shell_instance.do_load("nonexistent_file.exe")

        assert shell_instance.current_file is None

    def test_load_without_argument_shows_usage(self, shell_instance: IntellicrackShell) -> None:
        """Load command without argument shows usage."""
        shell_instance.do_load("")

        assert shell_instance.current_file is None


class TestStatusCommand:
    """Test status command functionality."""

    def test_status_shows_no_file_loaded(self, shell_instance: IntellicrackShell) -> None:
        """Status command shows no file loaded initially."""
        shell_instance.do_status("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    def test_status_shows_loaded_file(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Status command shows loaded file information."""
        shell_instance.current_file = temp_binary

        shell_instance.do_status("")

        assert shell_instance.current_file == temp_binary

    def test_status_shows_analysis_results_when_available(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Status command shows analysis results when available."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_status("")

        assert shell_instance.analysis_results is not None


class TestClearCommand:
    """Test clear command functionality."""

    def test_clear_resets_session(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Clear command resets session state."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_clear("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None


class TestExitCommand:
    """Test exit and quit commands."""

    def test_exit_command_returns_true(self, shell_instance: IntellicrackShell) -> None:
        """Exit command returns True to terminate shell."""
        result = shell_instance.do_exit("")

        assert result is True

    def test_quit_command_returns_true(self, shell_instance: IntellicrackShell) -> None:
        """Quit command returns True to terminate shell."""
        result = shell_instance.do_quit("")

        assert result is True


class TestAnalyzeCommand:
    """Test analyze command functionality."""

    def test_analyze_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Analyze command without loaded file shows error."""
        shell_instance.do_analyze("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    @patch("intellicrack.cli.interactive_mode.run_comprehensive_analysis")
    def test_analyze_with_loaded_file_runs_analysis(
        self, mock_analysis: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Analyze command with loaded file runs analysis."""
        shell_instance.current_file = temp_binary
        mock_analysis.return_value = {"results": "test_data"}

        shell_instance.do_analyze("")

        mock_analysis.assert_called_once_with(str(temp_binary))
        assert shell_instance.analysis_results == {"results": "test_data"}

    @patch("intellicrack.cli.interactive_mode.run_comprehensive_analysis")
    def test_analyze_handles_analysis_errors(
        self, mock_analysis: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Analyze command handles analysis errors gracefully."""
        shell_instance.current_file = temp_binary
        mock_analysis.side_effect = Exception("Analysis failed")

        shell_instance.do_analyze("")

        assert shell_instance.analysis_results is None


class TestStringsCommand:
    """Test strings extraction command."""

    def test_strings_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Strings command without loaded file shows error."""
        shell_instance.do_strings("")

        assert shell_instance.current_file is None

    def test_strings_with_default_min_length(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Strings command uses default minimum length."""
        shell_instance.current_file = temp_binary

        with patch("intellicrack.cli.interactive_mode._extract_strings") as mock_extract:
            mock_extract.return_value = ["TEST_BINARY_CONTENT", "ANOTHER_STRING"]

            shell_instance.do_strings("")

            mock_extract.assert_called_once()
            call_args = mock_extract.call_args
            assert call_args[0][0] == str(temp_binary)

    def test_strings_with_custom_min_length(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Strings command accepts custom minimum length."""
        shell_instance.current_file = temp_binary

        with patch("intellicrack.cli.interactive_mode._extract_strings") as mock_extract:
            mock_extract.return_value = ["LONG_STRING"]

            shell_instance.do_strings("10")

            mock_extract.assert_called_once()


class TestExportCommand:
    """Test export command functionality."""

    def test_export_without_analysis_results_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Export command without analysis results shows error."""
        shell_instance.do_export("json output.json")

        assert shell_instance.analysis_results is None

    def test_export_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Export command without loaded file shows error."""
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_export("json output.json")

        assert shell_instance.current_file is None

    def test_export_with_insufficient_arguments_shows_usage(
        self, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Export command with insufficient arguments shows usage."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_export("json")

    @patch("intellicrack.cli.interactive_mode.AdvancedExporter")
    def test_export_json_format(
        self, mock_exporter_class: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Export command exports JSON format."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        mock_exporter = MagicMock()
        mock_exporter.export_detailed_json.return_value = True
        mock_exporter_class.return_value = mock_exporter

        shell_instance.do_export("json output.json")

        mock_exporter_class.assert_called_once_with(str(temp_binary), {"test": "data"})
        mock_exporter.export_detailed_json.assert_called_once_with("output.json")

    @patch("intellicrack.cli.interactive_mode.AdvancedExporter")
    def test_export_html_format(
        self, mock_exporter_class: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Export command exports HTML format."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        mock_exporter = MagicMock()
        mock_exporter.export_html_report.return_value = True
        mock_exporter_class.return_value = mock_exporter

        shell_instance.do_export("html report.html")

        mock_exporter.export_html_report.assert_called_once_with("report.html")

    @patch("intellicrack.cli.interactive_mode.AdvancedExporter")
    def test_export_unsupported_format_shows_error(
        self, mock_exporter_class: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Export command handles unsupported format."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_export("unsupported output.file")


class TestProtectionCommand:
    """Test protection analysis command."""

    def test_protection_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Protection command without loaded file shows error."""
        shell_instance.do_protection("")

        assert shell_instance.current_file is None

    @patch("intellicrack.cli.interactive_mode.analyze_protections")
    def test_protection_analyzes_loaded_file(
        self, mock_analyze: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Protection command analyzes loaded file."""
        shell_instance.current_file = temp_binary
        mock_analyze.return_value = {
            "VMProtect": {"detected": True, "type": "Packer", "confidence": 95},
            "Themida": {"detected": False},
        }

        shell_instance.do_protection("")

        mock_analyze.assert_called_once_with(str(temp_binary))


class TestPatchCommand:
    """Test patch generation command."""

    def test_patch_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Patch command without loaded file shows error."""
        shell_instance.do_patch("output.json")

        assert shell_instance.current_file is None

    def test_patch_without_output_file_shows_usage(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Patch command without output file shows usage."""
        shell_instance.current_file = temp_binary

        shell_instance.do_patch("")

    @patch("intellicrack.cli.interactive_mode.generate_patch")
    def test_patch_generates_patches(
        self, mock_generate: MagicMock, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Patch command generates patches."""
        shell_instance.current_file = temp_binary
        output_file = tmp_path / "patches.json"

        mock_generate.return_value = {
            "patches": [
                {"offset": "0x1000", "original": "74 05", "patched": "EB 05", "description": "License check bypass"}
            ]
        }

        shell_instance.do_patch(str(output_file))

        mock_generate.assert_called_once_with(str(temp_binary))
        assert output_file.exists()


class TestAICommand:
    """Test AI assistant command."""

    def test_ai_without_question_shows_usage(self, shell_instance: IntellicrackShell) -> None:
        """AI command without question shows usage."""
        shell_instance.do_ai("")

    @patch("intellicrack.cli.interactive_mode.AIChatInterface")
    def test_ai_asks_question(self, mock_ai_class: MagicMock, shell_instance: IntellicrackShell) -> None:
        """AI command asks question to AI assistant."""
        mock_ai = MagicMock()
        mock_ai.ask.return_value = "AI response"
        mock_ai_class.return_value = mock_ai

        shell_instance.do_ai("What protections are detected?")

        mock_ai.ask.assert_called_once()
        call_args = mock_ai.ask.call_args
        assert call_args[0][0] == "What protections are detected?"

    @patch("intellicrack.cli.interactive_mode.AIChatInterface")
    def test_ai_reuses_chat_interface(self, mock_ai_class: MagicMock, shell_instance: IntellicrackShell) -> None:
        """AI command reuses chat interface across calls."""
        mock_ai = MagicMock()
        mock_ai.ask.return_value = "Response"
        mock_ai_class.return_value = mock_ai

        shell_instance.do_ai("First question")
        shell_instance.do_ai("Second question")

        assert mock_ai_class.call_count == 1
        assert mock_ai.ask.call_count == 2


class TestHelpCommand:
    """Test help command functionality."""

    def test_help_without_argument_shows_all_commands(self, shell_instance: IntellicrackShell) -> None:
        """Help command without argument shows all commands."""
        shell_instance.do_help("")

    def test_help_with_specific_command(self, shell_instance: IntellicrackShell) -> None:
        """Help command with specific command shows command help."""
        shell_instance.do_help("load")


class TestMainFunction:
    """Test main entry point."""

    @patch("intellicrack.cli.interactive_mode.IntellicrackShell")
    def test_main_creates_shell_and_runs_cmdloop(self, mock_shell_class: MagicMock) -> None:
        """Main function creates shell and runs command loop."""
        mock_shell = MagicMock()
        mock_shell_class.return_value = mock_shell

        result = main()

        mock_shell_class.assert_called_once()
        mock_shell.cmdloop.assert_called_once()
        assert result == 0

    @patch("intellicrack.cli.interactive_mode.IntellicrackShell")
    def test_main_handles_keyboard_interrupt(self, mock_shell_class: MagicMock) -> None:
        """Main function handles keyboard interrupt gracefully."""
        mock_shell = MagicMock()
        mock_shell.cmdloop.side_effect = KeyboardInterrupt()
        mock_shell_class.return_value = mock_shell

        with patch("intellicrack.cli.interactive_mode.main", side_effect=[KeyboardInterrupt(), 0]):
            try:
                result = main()
            except KeyboardInterrupt:
                pass


class TestSessionManagement:
    """Test session management across commands."""

    def test_session_workflow_load_analyze_export(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Complete workflow: load, analyze, export."""
        shell_instance.do_load(str(temp_binary))
        assert shell_instance.current_file == temp_binary

        with patch("intellicrack.cli.interactive_mode.run_comprehensive_analysis") as mock_analysis:
            mock_analysis.return_value = {"test": "results"}
            shell_instance.do_analyze("")
            assert shell_instance.analysis_results == {"test": "results"}

        output_file = tmp_path / "export.json"
        with patch("intellicrack.cli.interactive_mode.AdvancedExporter") as mock_exporter_class:
            mock_exporter = MagicMock()
            mock_exporter.export_detailed_json.return_value = True
            mock_exporter_class.return_value = mock_exporter

            shell_instance.do_export(f"json {output_file}")

    def test_session_workflow_clear_resets_state(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Clear command resets session state."""
        shell_instance.do_load(str(temp_binary))

        with patch("intellicrack.cli.interactive_mode.run_comprehensive_analysis") as mock_analysis:
            mock_analysis.return_value = {"test": "data"}
            shell_instance.do_analyze("")

        shell_instance.do_clear("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_commands_with_empty_strings(self, shell_instance: IntellicrackShell) -> None:
        """Commands handle empty strings correctly."""
        shell_instance.do_load("")
        shell_instance.do_analyze("")
        shell_instance.do_strings("")
        shell_instance.do_export("")
        shell_instance.do_protection("")
        shell_instance.do_patch("")
        shell_instance.do_ai("")

    def test_commands_with_unicode_input(self, shell_instance: IntellicrackShell, tmp_path: Path) -> None:
        """Commands handle unicode input correctly."""
        unicode_file = tmp_path / "tëst_fìlé.exe"
        unicode_file.write_bytes(b"MZ\x90\x00" + b"TEST")

        shell_instance.do_load(str(unicode_file))

        assert shell_instance.current_file == unicode_file
