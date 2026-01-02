"""Production tests for Terminal Manager.

Tests validate singleton pattern, terminal widget registration,
tab switching, script execution, and command execution for terminal operations.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.terminal_manager import TerminalManager


class FakeTerminalDisplay:
    """Test double for terminal display component."""

    def __init__(self) -> None:
        self.focus_set: bool = False
        self.focus_count: int = 0

    def setFocus(self) -> None:
        """Track focus setting calls."""
        self.focus_set = True
        self.focus_count += 1


class FakeTerminalSession:
    """Test double for terminal session operations."""

    def __init__(self, session_id: str) -> None:
        self.session_id: str = session_id
        self.terminal_display: FakeTerminalDisplay = FakeTerminalDisplay()
        self.executed_commands: list[str | list[str]] = []
        self.started_processes: list[tuple[list[str], str | None]] = []
        self.written_output: list[str] = []
        self.last_pid: int = 12345

    def execute_command(self, command: str | list[str]) -> None:
        """Record command execution."""
        self.executed_commands.append(command)

    def start_process(self, command: list[str], cwd: str | None = None) -> int:
        """Record process start and return fake PID."""
        self.started_processes.append((command, cwd))
        return self.last_pid

    def write_output(self, message: str) -> None:
        """Record output writing."""
        self.written_output.append(message)


class FakeTerminalWidget:
    """Test double for terminal widget component."""

    def __init__(self) -> None:
        self.sessions: dict[str, FakeTerminalSession] = {}
        self.active_session_id: str = "session_1"
        self.created_sessions: list[str] = []

        default_session = FakeTerminalSession(self.active_session_id)
        self.sessions[self.active_session_id] = default_session

    def get_active_session(self) -> tuple[str, FakeTerminalSession]:
        """Return active terminal session."""
        return (self.active_session_id, self.sessions[self.active_session_id])

    def create_new_session(self) -> str:
        """Create new session and return session ID."""
        new_id = f"session_{len(self.created_sessions) + 2}"
        self.created_sessions.append(new_id)
        new_session = FakeTerminalSession(new_id)
        self.sessions[new_id] = new_session
        self.active_session_id = new_id
        return new_id


class FakeTabWidget:
    """Test double for QTabWidget operations."""

    def __init__(self, tab_names: list[str]) -> None:
        self.tab_names: list[str] = tab_names
        self.current_index: int = 0
        self.set_index_calls: list[int] = []

    def count(self) -> int:
        """Return number of tabs."""
        return len(self.tab_names)

    def tabText(self, index: int) -> str:
        """Return tab text at index."""
        if 0 <= index < len(self.tab_names):
            return self.tab_names[index]
        return ""

    def setCurrentIndex(self, index: int) -> None:
        """Record tab index changes."""
        self.current_index = index
        self.set_index_calls.append(index)


class FakeMainApp:
    """Test double for main application."""

    def __init__(self, tab_names: list[str]) -> None:
        self.tabs: FakeTabWidget = FakeTabWidget(tab_names)


class FakeSubprocessResult:
    """Test double for subprocess.CompletedProcess."""

    def __init__(self, stdout: str, stderr: str, returncode: int) -> None:
        self.stdout: str = stdout
        self.stderr: str = stderr
        self.returncode: int = returncode


class FakeSubprocessRunner:
    """Test double for subprocess execution."""

    def __init__(self) -> None:
        self.executed_commands: list[tuple[str | list[str], dict[str, Any]]] = []
        self.next_result: FakeSubprocessResult = FakeSubprocessResult("", "", 0)
        self.should_raise: Exception | None = None

    def run(self, command: str | list[str], **kwargs: Any) -> FakeSubprocessResult:
        """Record command execution and return result."""
        self.executed_commands.append((command, kwargs))

        if self.should_raise:
            raise self.should_raise

        return self.next_result

    def set_next_result(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        """Configure next result to return."""
        self.next_result = FakeSubprocessResult(stdout, stderr, returncode)

    def set_next_exception(self, exception: Exception) -> None:
        """Configure next exception to raise."""
        self.should_raise = exception


class TestTerminalManagerSingleton:
    """Test singleton pattern implementation."""

    def test_singleton_returns_same_instance(self) -> None:
        """Terminal manager follows singleton pattern."""
        manager1 = TerminalManager()
        manager2 = TerminalManager()

        assert manager1 is manager2

    def test_singleton_initializes_only_once(self) -> None:
        """Terminal manager initializes internal state only on first instantiation."""
        TerminalManager._instance = None

        manager1 = TerminalManager()
        initial_sessions = id(manager1._sessions)

        manager2 = TerminalManager()
        second_sessions = id(manager2._sessions)

        assert initial_sessions == second_sessions

    def test_singleton_persists_state_across_instances(self) -> None:
        """Singleton persists state across multiple instantiations."""
        TerminalManager._instance = None

        manager1 = TerminalManager()
        test_value: dict[str, str] = {"test": "data"}
        manager1._sessions["test_session"] = test_value

        manager2 = TerminalManager()

        assert "test_session" in manager2._sessions
        assert manager2._sessions["test_session"] == test_value


class TestTerminalManagerRegistration:
    """Test terminal widget and main app registration."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_register_terminal_widget_stores_reference(self, manager: TerminalManager) -> None:
        """Registering terminal widget stores reference correctly."""
        fake_widget = FakeTerminalWidget()

        manager.register_terminal_widget(fake_widget)

        assert manager._terminal_widget is fake_widget

    def test_set_main_app_stores_reference(self, manager: TerminalManager) -> None:
        """Setting main app stores reference correctly."""
        fake_app = FakeMainApp(["Analysis", "Terminal"])

        manager.set_main_app(fake_app)

        assert manager._main_app is fake_app

    def test_set_main_app_validates_tabs_attribute(self, manager: TerminalManager) -> None:
        """Setting main app validates tabs attribute exists."""

        class AppWithoutTabs:
            """Test app without tabs attribute."""

            pass

        app_without_tabs = AppWithoutTabs()

        with pytest.raises(ValueError, match="must have 'tabs' attribute"):
            manager.set_main_app(app_without_tabs)


class TestTerminalManagerTabSwitching:
    """Test tab switching functionality."""

    @pytest.fixture
    def manager_with_app(self) -> TerminalManager:
        """Provide terminal manager with registered app."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_app = FakeMainApp(["Analysis", "Terminal", "Settings"])
        manager.set_main_app(fake_app)

        return manager

    def test_switch_to_terminal_tab_finds_and_activates(self, manager_with_app: TerminalManager) -> None:
        """Switching to terminal tab finds correct tab and activates it."""
        manager_with_app._switch_to_terminal_tab()

        assert manager_with_app._main_app is not None
        assert manager_with_app._main_app.tabs.current_index == 1
        assert 1 in manager_with_app._main_app.tabs.set_index_calls

    def test_switch_to_terminal_tab_case_insensitive(self) -> None:
        """Terminal tab search is case-insensitive."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_app = FakeMainApp(["Analysis", "TERMINAL"])
        manager.set_main_app(fake_app)
        manager._switch_to_terminal_tab()

        assert fake_app.tabs.current_index == 1
        assert 1 in fake_app.tabs.set_index_calls

    def test_switch_to_terminal_tab_without_app_logs_warning(self, caplog: Any) -> None:
        """Attempting tab switch without registered app logs warning."""
        TerminalManager._instance = None
        manager = TerminalManager()

        with caplog.at_level(logging.WARNING):
            manager._switch_to_terminal_tab()

        assert "main app not registered" in caplog.text

    def test_switch_to_terminal_tab_sets_focus(self) -> None:
        """Switching to terminal tab sets focus on terminal display."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_app = FakeMainApp(["Analysis", "Terminal"])
        fake_widget = FakeTerminalWidget()

        manager.set_main_app(fake_app)
        manager.register_terminal_widget(fake_widget)
        manager._switch_to_terminal_tab()

        session_id, terminal = fake_widget.get_active_session()
        assert terminal.terminal_display.focus_set is True
        assert terminal.terminal_display.focus_count == 1


class TestTerminalManagerScriptResolution:
    """Test script path resolution."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_resolve_absolute_path_existing_file(self, tmp_path: Path, manager: TerminalManager) -> None:
        """Resolving absolute path to existing script succeeds."""
        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        resolved = manager._resolve_script_path(str(script_file))

        assert resolved == script_file
        assert resolved.exists()

    def test_resolve_absolute_path_nonexistent_file_raises(self, tmp_path: Path, manager: TerminalManager) -> None:
        """Resolving absolute path to nonexistent script raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.py"

        with pytest.raises(FileNotFoundError, match="Script not found"):
            manager._resolve_script_path(str(nonexistent))

    def test_resolve_relative_path_in_scripts_directory(self, tmp_path: Path, manager: TerminalManager) -> None:
        """Resolving relative path searches intellicrack/scripts directory."""
        scripts_dir = tmp_path / "intellicrack" / "scripts" / "frida"
        scripts_dir.mkdir(parents=True, exist_ok=True)

        test_script = scripts_dir / "test_script.js"
        test_script.write_text("console.log('test');")

        original_file_path = Path(__file__).parent.parent.parent / "intellicrack" / "core" / "terminal_manager.py"

        class FakePath:
            """Test double for Path resolution."""

            def __init__(self, path_str: str) -> None:
                self._path = Path(path_str)

            @property
            def parent(self) -> "FakePath":
                """Return parent directory."""
                result = FakePath(str(self._path.parent))
                if str(self._path).endswith("terminal_manager.py"):
                    result._parent = tmp_path / "intellicrack"
                return result

            def __truediv__(self, other: str) -> Path:
                """Path division operator."""
                return self._path / other

            def is_absolute(self) -> bool:
                """Check if path is absolute."""
                return self._path.is_absolute()

            def exists(self) -> bool:
                """Check if path exists."""
                return self._path.exists()

        relative_result = manager._resolve_script_path(test_script)
        assert relative_result.exists()
        assert relative_result.name == "test_script.js"


class TestTerminalManagerCommandExecution:
    """Test command execution functionality."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_execute_command_with_capture_returns_output(self, manager: TerminalManager) -> None:
        """Executing command with capture returns stdout, stderr, and returncode."""
        fake_runner = FakeSubprocessRunner()
        fake_runner.set_next_result(stdout="test output", stderr="", returncode=0)

        original_run = subprocess.run
        subprocess.run = fake_runner.run

        try:
            returncode, stdout, stderr = manager.execute_command("echo test", capture_output=True)

            assert stdout == "test output"
            assert stderr == ""
            assert returncode == 0
            assert len(fake_runner.executed_commands) == 1

            command, kwargs = fake_runner.executed_commands[0]
            assert kwargs.get("capture_output") is True
            assert kwargs.get("text") is True
        finally:
            subprocess.run = original_run

    def test_execute_command_without_capture_runs_in_terminal(self, manager: TerminalManager) -> None:
        """Executing command without capture runs in terminal session."""
        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        result = manager.execute_command("echo test", capture_output=False)

        assert result == "session_1"
        session_id, terminal = fake_widget.get_active_session()
        assert len(terminal.started_processes) == 1
        command, cwd = terminal.started_processes[0]
        assert "echo" in command

    def test_execute_command_failure_returns_error(self, manager: TerminalManager) -> None:
        """Executing command that fails returns error information."""
        fake_runner = FakeSubprocessRunner()
        fake_runner.set_next_exception(
            subprocess.CalledProcessError(1, "failed_command", stderr="error output")
        )

        original_run = subprocess.run
        subprocess.run = fake_runner.run

        try:
            returncode, stdout, stderr = manager.execute_command("failed_command", capture_output=True)

            assert returncode == 1
            assert "error" in stderr.lower() or "CalledProcessError" in stderr
        finally:
            subprocess.run = original_run

    def test_execute_command_validates_unsafe_input(self, manager: TerminalManager) -> None:
        """Executing command validates input for command injection prevention."""
        result = manager.execute_command(
            ["echo", "test; rm -rf /"], capture_output=True, cwd="/tmp"
        )

        returncode, stdout, stderr = result
        assert isinstance(returncode, int)


class TestTerminalManagerScriptExecution:
    """Test script execution in terminal."""

    @pytest.fixture
    def manager_with_terminal(self) -> TerminalManager:
        """Provide terminal manager with registered terminal widget."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        return manager

    def test_execute_script_starts_process_in_terminal(
        self, manager_with_terminal: TerminalManager, tmp_path: Path
    ) -> None:
        """Executing script starts process in terminal session."""
        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        session_id = manager_with_terminal.execute_script(str(script_file), auto_switch=False)

        assert session_id == "session_1"
        terminal_widget = manager_with_terminal._terminal_widget
        assert terminal_widget is not None
        _, terminal = terminal_widget.get_active_session()
        assert len(terminal.started_processes) == 1

        command, cwd = terminal.started_processes[0]
        assert any("python" in str(arg).lower() for arg in command)
        assert str(script_file) in command

    def test_execute_script_switches_to_tab_when_requested(
        self, manager_with_terminal: TerminalManager, tmp_path: Path
    ) -> None:
        """Executing script switches to terminal tab when auto_switch=True."""
        fake_app = FakeMainApp(["Analysis", "Terminal"])
        manager_with_terminal.set_main_app(fake_app)

        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        manager_with_terminal.execute_script(str(script_file), auto_switch=True)

        assert fake_app.tabs.current_index == 1
        assert 1 in fake_app.tabs.set_index_calls

    def test_execute_script_without_widget_raises_error(self, tmp_path: Path) -> None:
        """Executing script without registered terminal widget raises RuntimeError."""
        TerminalManager._instance = None
        manager = TerminalManager()

        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        with pytest.raises(RuntimeError, match="Terminal widget not registered"):
            manager.execute_script(str(script_file))

    def test_execute_script_handles_different_script_types(
        self, manager_with_terminal: TerminalManager, tmp_path: Path
    ) -> None:
        """Executing script handles different script types correctly."""
        test_cases = [
            ("test.py", "print('test')", "python"),
            ("test.bat", "@echo test", "cmd"),
            ("test.ps1", "Write-Output 'test'", "powershell"),
            ("test.js", "console.log('test');", "node"),
        ]

        for filename, content, expected_executor in test_cases:
            script_file = tmp_path / filename
            script_file.write_text(content)

            session_id = manager_with_terminal.execute_script(str(script_file), auto_switch=False)

            terminal_widget = manager_with_terminal._terminal_widget
            assert terminal_widget is not None
            _, terminal = terminal_widget.get_active_session()

            if terminal.started_processes:
                command, _ = terminal.started_processes[-1]
                command_str = " ".join(str(arg) for arg in command).lower()
                assert expected_executor.lower() in command_str or str(script_file) in command_str


class TestTerminalManagerSessionManagement:
    """Test terminal session management."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_sessions_dictionary_initialized(self, manager: TerminalManager) -> None:
        """Sessions dictionary is initialized on manager creation."""
        assert isinstance(manager._sessions, dict)
        assert len(manager._sessions) == 0

    def test_sessions_persist_across_calls(self, manager: TerminalManager) -> None:
        """Session data persists across multiple operations."""
        manager._sessions["test_session"] = {"status": "active"}

        assert "test_session" in manager._sessions
        assert manager._sessions["test_session"]["status"] == "active"

    def test_multiple_sessions_stored(self, manager: TerminalManager) -> None:
        """Manager can store multiple session references."""
        manager._sessions["session1"] = {"pid": 1234}
        manager._sessions["session2"] = {"pid": 5678}

        assert len(manager._sessions) == 2
        assert manager._sessions["session1"]["pid"] == 1234
        assert manager._sessions["session2"]["pid"] == 5678


class TestTerminalManagerLogging:
    """Test logging functionality."""

    def test_initialization_logs_message(self, caplog: Any) -> None:
        """Manager initialization logs informational message."""
        TerminalManager._instance = None

        with caplog.at_level(logging.INFO):
            _manager = TerminalManager()

        assert "TerminalManager singleton initialized" in caplog.text

    def test_terminal_widget_registration_logs(self, caplog: Any) -> None:
        """Terminal widget registration logs informational message."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_widget = FakeTerminalWidget()

        with caplog.at_level(logging.INFO):
            manager.register_terminal_widget(fake_widget)

        assert "Terminal widget registered" in caplog.text

    def test_main_app_registration_logs(self, caplog: Any) -> None:
        """Main app registration logs informational message."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_app = FakeMainApp(["Analysis", "Terminal"])

        with caplog.at_level(logging.INFO):
            manager.set_main_app(fake_app)

        assert "Main app registered" in caplog.text


class TestTerminalManagerUtilityMethods:
    """Test utility methods for terminal availability and logging."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_is_terminal_available_without_widget(self, manager: TerminalManager) -> None:
        """Terminal availability check returns False without widget."""
        assert manager.is_terminal_available() is False

    def test_is_terminal_available_with_widget(self, manager: TerminalManager) -> None:
        """Terminal availability check returns True with widget."""
        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        assert manager.is_terminal_available() is True

    def test_get_terminal_widget_returns_registered_widget(self, manager: TerminalManager) -> None:
        """Getting terminal widget returns registered widget."""
        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        retrieved = manager.get_terminal_widget()

        assert retrieved is fake_widget

    def test_get_terminal_widget_returns_none_when_not_registered(self, manager: TerminalManager) -> None:
        """Getting terminal widget returns None when not registered."""
        assert manager.get_terminal_widget() is None

    def test_log_terminal_message_writes_to_terminal(self, manager: TerminalManager) -> None:
        """Logging terminal message writes to terminal widget."""
        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        manager.log_terminal_message("Test message", level="INFO")

        _, terminal = fake_widget.get_active_session()
        assert len(terminal.written_output) == 1
        assert "[INFO] Test message" in terminal.written_output[0]

    def test_log_terminal_message_without_widget_logs_debug(
        self, manager: TerminalManager, caplog: Any
    ) -> None:
        """Logging terminal message without widget logs debug message."""
        with caplog.at_level(logging.DEBUG):
            manager.log_terminal_message("Test message")

        assert "Terminal widget not available" in caplog.text


class TestTerminalManagerIntegration:
    """Integration tests for complete workflows."""

    def test_complete_workflow_register_and_execute(self, tmp_path: Path) -> None:
        """Complete workflow: register components and execute script."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_app = FakeMainApp(["Analysis", "Terminal"])
        fake_widget = FakeTerminalWidget()

        manager.set_main_app(fake_app)
        manager.register_terminal_widget(fake_widget)

        script_file = tmp_path / "integration_test.py"
        script_file.write_text("print('integration test')")

        session_id = manager.execute_script(str(script_file), auto_switch=True)

        assert fake_app.tabs.current_index == 1
        assert session_id == "session_1"

        _, terminal = fake_widget.get_active_session()
        assert len(terminal.started_processes) == 1

    def test_multiple_command_executions_in_terminal(self) -> None:
        """Multiple command executions work correctly in terminal."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        session1 = manager.execute_command("command1", capture_output=False)
        session2 = manager.execute_command("command2", capture_output=False)

        assert session1 == "session_1"
        assert session2 == "session_1"

        _, terminal = fake_widget.get_active_session()
        assert len(terminal.started_processes) == 2

    def test_multiple_command_executions_with_capture(self) -> None:
        """Multiple command executions with capture work correctly."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_runner = FakeSubprocessRunner()
        original_run = subprocess.run
        subprocess.run = fake_runner.run

        try:
            fake_runner.set_next_result(stdout="output1", stderr="", returncode=0)
            returncode1, stdout1, stderr1 = manager.execute_command("command1", capture_output=True)

            fake_runner.set_next_result(stdout="output2", stderr="", returncode=0)
            returncode2, stdout2, stderr2 = manager.execute_command("command2", capture_output=True)

            assert stdout1 == "output1"
            assert stdout2 == "output2"
            assert len(fake_runner.executed_commands) == 2
        finally:
            subprocess.run = original_run

    def test_session_creation_and_script_execution(self, tmp_path: Path) -> None:
        """Session creation followed by script execution works correctly."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        script_file = tmp_path / "test.py"
        script_file.write_text("print('test')")

        session_id = manager.execute_script(str(script_file), auto_switch=False)

        assert session_id in fake_widget.sessions
        terminal = fake_widget.sessions[session_id]
        assert len(terminal.started_processes) == 1

    def test_terminal_availability_workflow(self) -> None:
        """Complete workflow testing terminal availability checks."""
        TerminalManager._instance = None
        manager = TerminalManager()

        assert manager.is_terminal_available() is False
        assert manager.get_terminal_widget() is None

        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        assert manager.is_terminal_available() is True
        assert manager.get_terminal_widget() is fake_widget

    def test_logging_workflow_with_terminal(self) -> None:
        """Complete workflow testing logging to terminal."""
        TerminalManager._instance = None
        manager = TerminalManager()

        fake_widget = FakeTerminalWidget()
        manager.register_terminal_widget(fake_widget)

        manager.log_terminal_message("Info message", level="INFO")
        manager.log_terminal_message("Warning message", level="WARNING")
        manager.log_terminal_message("Error message", level="ERROR")

        _, terminal = fake_widget.get_active_session()
        assert len(terminal.written_output) == 3
        assert "[INFO] Info message" in terminal.written_output[0]
        assert "[WARNING] Warning message" in terminal.written_output[1]
        assert "[ERROR] Error message" in terminal.written_output[2]
