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
from typing import Any, Generator

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.tabs.adobe_injector_tab import AdobeInjectorTab


class FakeProcess:
    """Test double for subprocess.Popen process."""

    def __init__(self, output_lines: list[bytes] | None = None) -> None:
        self.output_lines = output_lines or [b""]
        self.line_index = 0
        self.stdout = self
        self.stderr = self
        self.stdin = None
        self.returncode: int | None = None
        self.poll_called = False

    def readline(self) -> bytes:
        """Read next output line."""
        if self.line_index >= len(self.output_lines):
            return b""
        line = self.output_lines[self.line_index]
        self.line_index += 1
        return line

    def poll(self) -> int | None:
        """Check if process has terminated."""
        self.poll_called = True
        return self.returncode


class FakePopen:
    """Test double for subprocess.Popen."""

    def __init__(self) -> None:
        self.called = False
        self.call_count = 0
        self.last_args: list[str] | None = None
        self.last_kwargs: dict[str, Any] = {}
        self.process_to_return: FakeProcess = FakeProcess()

    def __call__(self, args: list[str], **kwargs: Any) -> FakeProcess:
        """Create fake process."""
        self.called = True
        self.call_count += 1
        self.last_args = args
        self.last_kwargs = kwargs
        return self.process_to_return

    @property
    def call_args(self) -> Any:
        """Return call arguments in Mock-compatible format."""
        class CallArgs:
            def __init__(self, args: list[str], kwargs: dict[str, Any]) -> None:
                self.args = (args,)
                self.kwargs = kwargs

        return CallArgs(self.last_args or [], self.last_kwargs)


class FakeTerminalManager:
    """Test double for terminal manager."""

    def __init__(self) -> None:
        self.terminal_available = True
        self.execute_command_called = False
        self.execute_call_count = 0
        self.last_command: str | list[str] | None = None
        self.session_id_to_return = "test_session_id"

    def is_terminal_available(self) -> bool:
        """Check if terminal is available."""
        return self.terminal_available

    def execute_command(self, command: str | list[str]) -> str:
        """Execute command in terminal."""
        self.execute_command_called = True
        self.execute_call_count += 1
        self.last_command = command
        return self.session_id_to_return


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    existing_app = QApplication.instance()
    if existing_app is None:
        return QApplication(sys.argv)
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    return existing_app


@pytest.fixture
def shared_context() -> dict[str, Any]:
    """Create shared context with minimal dependencies."""
    return {
        "app_context": None,
        "task_manager": None,
        "main_window": None,
    }


@pytest.fixture
def adobe_tab(
    qapp: QApplication, shared_context: dict[str, Any]
) -> Generator[AdobeInjectorTab, None, None]:
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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Subprocess launch in hidden mode creates valid process with output capture."""
        fake_popen = FakePopen()
        fake_popen.process_to_return = FakeProcess()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: mock_adobe_injector_exe.parent.parent.parent,
        )
        monkeypatch.setattr("subprocess.Popen", fake_popen)

        adobe_tab.launch_subprocess(hidden=True)

        assert fake_popen.called
        assert fake_popen.last_kwargs["stdout"] == subprocess.PIPE
        assert fake_popen.last_kwargs["stderr"] == subprocess.PIPE
        assert fake_popen.last_kwargs["stdin"] == subprocess.PIPE
        assert fake_popen.last_kwargs["shell"] is False
        assert "startupinfo" in fake_popen.last_kwargs

    def test_subprocess_launch_visible_no_output_capture(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Subprocess launch in visible mode creates process without output capture."""
        fake_popen = FakePopen()
        fake_popen.process_to_return = FakeProcess()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: mock_adobe_injector_exe.parent.parent.parent,
        )
        monkeypatch.setattr("subprocess.Popen", fake_popen)

        adobe_tab.launch_subprocess(hidden=False)

        assert fake_popen.called
        assert "stdout" not in fake_popen.last_kwargs or fake_popen.last_kwargs.get("stdout") != subprocess.PIPE
        assert fake_popen.last_kwargs["shell"] is False

    def test_subprocess_command_argument_parsing(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Subprocess correctly parses and passes command line arguments."""
        fake_popen = FakePopen()
        fake_popen.process_to_return = FakeProcess()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: mock_adobe_injector_exe.parent.parent.parent,
        )
        monkeypatch.setattr("subprocess.Popen", fake_popen)

        assert adobe_tab.cmd_args is not None, "cmd_args should be initialized"
        adobe_tab.cmd_args.setText("/silent /path:C:\\Test")
        adobe_tab.launch_subprocess(hidden=True)

        assert fake_popen.called
        cmd = fake_popen.last_args

        assert isinstance(cmd, list)
        assert len(cmd) >= 3
        assert "/silent" in cmd
        assert "/path:C:\\Test" in cmd

    def test_subprocess_fails_when_exe_missing(
        self,
        adobe_tab: AdobeInjectorTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Subprocess launch fails gracefully when executable not found."""
        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: Path("/nonexistent"),
        )

        adobe_tab.launch_subprocess(hidden=True)

        assert adobe_tab.adobe_injector_process is None


class TestAdobeInjectorTabTerminalExecution:
    """Tests for terminal execution capabilities."""

    def test_terminal_execution_sends_command(
        self,
        adobe_tab: AdobeInjectorTab,
        mock_adobe_injector_exe: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Terminal execution sends command to terminal manager."""
        fake_tm = FakeTerminalManager()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: mock_adobe_injector_exe.parent.parent.parent,
        )
        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager",
            lambda: fake_tm,
        )

        adobe_tab.execute_in_terminal("AdobeInjector.exe /scan")

        assert fake_tm.execute_command_called
        assert fake_tm.last_command is not None
        assert "AdobeInjector.exe" in str(fake_tm.last_command) or isinstance(fake_tm.last_command, list)

    def test_terminal_execution_fails_when_unavailable(
        self,
        adobe_tab: AdobeInjectorTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Terminal execution handles unavailable terminal gracefully."""
        fake_tm = FakeTerminalManager()
        fake_tm.terminal_available = False

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager",
            lambda: fake_tm,
        )

        adobe_tab.execute_in_terminal("test command")

        assert not fake_tm.execute_command_called


class TestAdobeInjectorTabConfiguration:
    """Tests for configuration file generation."""

    def test_silent_config_creation_generates_valid_json(
        self,
        adobe_tab: AdobeInjectorTab,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Silent config creation generates valid JSON configuration file."""
        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: tmp_path,
        )

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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Resource modification creates valid rebranding configuration."""
        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: tmp_path,
        )

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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Terminal execution emits injector_started signal."""
        signal_emitted = False
        signal_data = None

        def signal_handler(data: str) -> None:
            nonlocal signal_emitted, signal_data
            signal_emitted = True
            signal_data = data

        adobe_tab.injector_started.connect(signal_handler)

        fake_tm = FakeTerminalManager()

        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_project_root",
            lambda: mock_adobe_injector_exe.parent.parent.parent,
        )
        monkeypatch.setattr(
            "intellicrack.ui.tabs.adobe_injector_tab.get_terminal_manager",
            lambda: fake_tm,
        )

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
        assert adobe_tab.method_tabs is not None, "method_tabs should be initialized"

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
        fake_process: Any = FakeProcess(output_lines=[
            b"Line 1\n",
            b"Line 2\n",
            b"",
        ])
        adobe_tab.adobe_injector_process = fake_process

        adobe_tab.monitor_subprocess()

        assert adobe_tab.subprocess_output is not None, "subprocess_output should be initialized"
        output_text = adobe_tab.subprocess_output.toPlainText()
        assert "Line 1" in output_text
        assert "Line 2" in output_text
        assert "Process terminated" in output_text
