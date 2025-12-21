"""Production tests for AdobeInjectorTab subprocess execution and configuration.

This module validates that AdobeInjectorTab correctly orchestrates Adobe Injector
integration through multiple execution methods (subprocess, terminal, embedded).

Tests prove real subprocess management capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.tabs.adobe_injector_tab import AdobeInjectorTab


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture
def shared_context() -> dict[str, Any]:
    """Create shared context with minimal dependencies."""
    return {
        "app_context": None,
        "task_manager": None,
        "main_window": None,
    }


@pytest.fixture
def adobe_tab(qapp: QApplication, shared_context: dict[str, Any]) -> AdobeInjectorTab:
    """Create AdobeInjectorTab instance."""
    tab = AdobeInjectorTab(shared_context)
    yield tab
    tab.cleanup()


@pytest.fixture
def mock_adobe_injector_exe(tmp_path: Path) -> Path:
    """Create mock Adobe Injector executable."""
    tools_dir = tmp_path / "tools" / "AdobeInjector"
    tools_dir.mkdir(parents=True)

    exe_path = tools_dir / "AdobeInjector.exe"
    exe_path.write_text("Mock Adobe Injector")

    return exe_path


class TestAdobeInjectorTabSubprocessExecution:
    """Tests for subprocess execution capabilities."""

    def test_subprocess_launch_hidden_creates_process(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
    ) -> None:
        """Subprocess launch in hidden mode creates valid process with output capture."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=mock_adobe_injector_exe.parent.parent.parent):
            with patch("subprocess.Popen") as mock_popen:
                mock_process = Mock()
                mock_process.stdout.readline.return_value = b""
                mock_popen.return_value = mock_process

                adobe_tab.launch_subprocess(hidden=True)

                assert mock_popen.called
                call_args = mock_popen.call_args

                assert call_args.kwargs["stdout"] == subprocess.PIPE
                assert call_args.kwargs["stderr"] == subprocess.PIPE
                assert call_args.kwargs["stdin"] == subprocess.PIPE
                assert call_args.kwargs["shell"] is False
                assert "startupinfo" in call_args.kwargs

    def test_subprocess_launch_visible_no_output_capture(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
    ) -> None:
        """Subprocess launch in visible mode creates process without output capture."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=mock_adobe_injector_exe.parent.parent.parent):
            with patch("subprocess.Popen") as mock_popen:
                mock_process = Mock()
                mock_popen.return_value = mock_process

                adobe_tab.launch_subprocess(hidden=False)

                assert mock_popen.called
                call_args = mock_popen.call_args

                assert "stdout" not in call_args.kwargs or call_args.kwargs.get("stdout") != subprocess.PIPE
                assert call_args.kwargs["shell"] is False

    def test_subprocess_command_argument_parsing(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
    ) -> None:
        """Subprocess correctly parses and passes command line arguments."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=mock_adobe_injector_exe.parent.parent.parent):
            with patch("subprocess.Popen") as mock_popen:
                mock_process = Mock()
                mock_process.stdout.readline.return_value = b""
                mock_popen.return_value = mock_process

                adobe_tab.cmd_args.setText("/silent /path:C:\\Test")
                adobe_tab.launch_subprocess(hidden=True)

                assert mock_popen.called
                cmd = mock_popen.call_args.args[0]

                assert isinstance(cmd, list)
                assert len(cmd) >= 3
                assert "/silent" in cmd
                assert "/path:C:\\Test" in cmd

    def test_subprocess_fails_when_exe_missing(
        self,
        adobe_tab: AdobeInjectorTab,
    ) -> None:
        """Subprocess launch fails gracefully when executable not found."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=Path("/nonexistent")):
            adobe_tab.launch_subprocess(hidden=True)

            assert adobe_tab.adobe_injector_process is None


class TestAdobeInjectorTabTerminalExecution:
    """Tests for terminal execution capabilities."""

    def test_terminal_execution_sends_command(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
    ) -> None:
        """Terminal execution sends command to terminal manager."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=mock_adobe_injector_exe.parent.parent.parent):
            with patch("intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager") as mock_get_tm:
                mock_tm = Mock()
                mock_tm.is_terminal_available.return_value = True
                mock_tm.execute_command.return_value = "test_session_id"
                mock_get_tm.return_value = mock_tm

                adobe_tab.execute_in_terminal("AdobeInjector.exe /scan")

                assert mock_tm.execute_command.called
                call_args = mock_tm.execute_command.call_args.args[0]
                assert "AdobeInjector.exe" in call_args or isinstance(call_args, list)

    def test_terminal_execution_fails_when_unavailable(
        self,
        adobe_tab: AdobeInjectorTab,
    ) -> None:
        """Terminal execution handles unavailable terminal gracefully."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager") as mock_get_tm:
            mock_tm = Mock()
            mock_tm.is_terminal_available.return_value = False
            mock_get_tm.return_value = mock_tm

            adobe_tab.execute_in_terminal("test command")

            assert not mock_tm.execute_command.called


class TestAdobeInjectorTabConfiguration:
    """Tests for configuration file generation."""

    def test_silent_config_creation_generates_valid_json(
        self,
        adobe_tab: AdobeInjectorTab,
        tmp_path: Path,
    ) -> None:
        """Silent config creation generates valid JSON configuration file."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=tmp_path):
            adobe_tab.create_silent_config()

            config_path = tmp_path / "tools" / "AdobeInjector" / "silent_config.json"
            assert config_path.exists()

            with open(config_path) as f:
                config = json.load(f)

            assert config["auto_scan"] is True
            assert config["auto_patch"] is True
            assert config["target_path"] == "C:\\Program Files\\Adobe"
            assert config["backup_files"] is True
            assert config["silent_mode"] is True

    def test_rebranding_config_creation_generates_valid_json(
        self,
        adobe_tab: AdobeInjectorTab,
        tmp_path: Path,
    ) -> None:
        """Resource modification creates valid rebranding configuration."""
        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=tmp_path):
            adobe_tab.modify_resources()

            config_path = tmp_path / "tools" / "AdobeInjector" / "rebrand.json"
            assert config_path.exists()

            with open(config_path) as f:
                rebrand = json.load(f)

            assert rebrand["ProductName"] == "Adobe Injector"
            assert rebrand["CompanyName"] == "Intellicrack"
            assert "FileDescription" in rebrand


class TestAdobeInjectorTabSignalEmission:
    """Tests for signal emission on operations."""

    def test_terminal_execution_emits_injector_started_signal(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
    ) -> None:
        """Terminal execution emits injector_started signal."""
        signal_emitted = False
        signal_data = None

        def signal_handler(data: str) -> None:
            nonlocal signal_emitted, signal_data
            signal_emitted = True
            signal_data = data

        adobe_tab.injector_started.connect(signal_handler)

        with patch("intellicrack.ui.tabs.adobe_injector_tab.get_project_root", return_value=mock_adobe_injector_exe.parent.parent.parent):
            with patch("intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager") as mock_get_tm:
                mock_tm = Mock()
                mock_tm.is_terminal_available.return_value = True
                mock_tm.execute_command.return_value = "test_session"
                mock_get_tm.return_value = mock_tm

                adobe_tab.execute_in_terminal("test command")

        assert signal_emitted
        assert signal_data == "Command sent to terminal"


class TestAdobeInjectorTabIntegrationMethods:
    """Tests for different integration method switching."""

    def test_method_selector_switches_tabs(
        self,
        adobe_tab: AdobeInjectorTab,
    ) -> None:
        """Method selector correctly switches between integration tabs."""
        adobe_tab.on_method_changed("Subprocess Control")
        assert adobe_tab.method_tabs.currentIndex() == 1

        adobe_tab.on_method_changed("Terminal Execution")
        assert adobe_tab.method_tabs.currentIndex() == 2

        adobe_tab.on_method_changed("Embedded Window (Native)")
        assert adobe_tab.method_tabs.currentIndex() == 0


class TestAdobeInjectorTabProcessMonitoring:
    """Tests for subprocess output monitoring."""

    def test_monitor_subprocess_reads_output_lines(
        self,
        adobe_tab: AdobeInjectorTab,
    ) -> None:
        """Subprocess monitor reads and displays output lines."""
        mock_process = Mock()
        mock_process.stdout.readline.side_effect = [
            b"Line 1\n",
            b"Line 2\n",
            b"",
        ]
        adobe_tab.adobe_injector_process = mock_process

        adobe_tab.monitor_subprocess()

        output_text = adobe_tab.subprocess_output.toPlainText()
        assert "Line 1" in output_text
        assert "Line 2" in output_text
        assert "Process terminated" in output_text
