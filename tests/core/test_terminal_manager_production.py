"""Production tests for Terminal Manager.

Tests validate singleton pattern, terminal widget registration,
tab switching, script execution, and command execution for terminal operations.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.terminal_manager import TerminalManager


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
        test_value = {"test": "data"}
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
        mock_widget = Mock()

        manager.register_terminal_widget(mock_widget)

        assert manager._terminal_widget is mock_widget

    def test_set_main_app_stores_reference(self, manager: TerminalManager) -> None:
        """Setting main app stores reference correctly."""
        mock_app = Mock()
        mock_app.tabs = Mock()

        manager.set_main_app(mock_app)

        assert manager._main_app is mock_app

    def test_set_main_app_validates_tabs_attribute(self, manager: TerminalManager) -> None:
        """Setting main app validates tabs attribute exists."""
        mock_app = Mock(spec=[])

        with pytest.raises(ValueError, match="must have 'tabs' attribute"):
            manager.set_main_app(mock_app)


class TestTerminalManagerTabSwitching:
    """Test tab switching functionality."""

    @pytest.fixture
    def manager_with_app(self) -> TerminalManager:
        """Provide terminal manager with registered app."""
        TerminalManager._instance = None
        manager = TerminalManager()

        mock_app = Mock()
        mock_tabs = Mock()
        mock_tabs.count.return_value = 3
        mock_tabs.tabText.side_effect = ["Analysis", "Terminal", "Settings"]
        mock_app.tabs = mock_tabs

        manager.set_main_app(mock_app)

        return manager

    def test_switch_to_terminal_tab_finds_and_activates(self, manager_with_app: TerminalManager) -> None:
        """Switching to terminal tab finds correct tab and activates it."""
        manager_with_app._switch_to_terminal_tab()

        assert manager_with_app._main_app is not None
        manager_with_app._main_app.tabs.setCurrentIndex.assert_called_once_with(1)

    def test_switch_to_terminal_tab_case_insensitive(self) -> None:
        """Terminal tab search is case-insensitive."""
        TerminalManager._instance = None
        manager = TerminalManager()

        mock_app = Mock()
        mock_tabs = Mock()
        mock_tabs.count.return_value = 2
        mock_tabs.tabText.side_effect = ["Analysis", "TERMINAL"]
        mock_app.tabs = mock_tabs

        manager.set_main_app(mock_app)
        manager._switch_to_terminal_tab()

        mock_tabs.setCurrentIndex.assert_called_once_with(1)

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

        mock_app = Mock()
        mock_tabs = Mock()
        mock_tabs.count.return_value = 2
        mock_tabs.tabText.side_effect = ["Analysis", "Terminal"]
        mock_app.tabs = mock_tabs

        mock_terminal_widget = Mock()
        mock_terminal_display = Mock()
        mock_terminal = Mock()
        mock_terminal.terminal_display = mock_terminal_display
        mock_terminal_widget.get_active_session.return_value = ("session_1", mock_terminal)

        manager.set_main_app(mock_app)
        manager.register_terminal_widget(mock_terminal_widget)
        manager._switch_to_terminal_tab()

        mock_terminal_display.setFocus.assert_called_once()


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
        with patch("intellicrack.core.terminal_manager.Path") as mock_path_class:
            mock_input_path = Mock()
            mock_input_path.is_absolute.return_value = False

            mock_scripts_dir = Mock()
            mock_resolved_script = Mock()
            mock_resolved_script.exists.return_value = True

            mock_scripts_dir.__truediv__ = Mock(return_value=mock_resolved_script)

            mock_path_class.return_value = mock_input_path
            mock_path_class.side_effect = [mock_input_path, mock_scripts_dir]

            mock_file = Mock()
            mock_file.parent.parent = mock_scripts_dir

            with patch("intellicrack.core.terminal_manager.__file__", str(tmp_path / "terminal_manager.py")):
                result = manager._resolve_script_path("frida/test_script.js")


class TestTerminalManagerCommandExecution:
    """Test command execution functionality."""

    @pytest.fixture
    def manager(self) -> TerminalManager:
        """Provide fresh terminal manager instance."""
        TerminalManager._instance = None
        return TerminalManager()

    def test_execute_command_with_capture(self, manager: TerminalManager) -> None:
        """Executing command with capture returns stdout."""
        with patch("intellicrack.core.terminal_manager.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.stdout = "test output"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            output = manager.execute_command("echo test", capture=True)

            assert output == "test output"
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            assert "echo test" in args[0] or "echo test" == args[0]
            assert kwargs.get("capture_output") is True
            assert kwargs.get("text") is True

    def test_execute_command_without_capture(self, manager: TerminalManager) -> None:
        """Executing command without capture runs directly."""
        with patch("intellicrack.core.terminal_manager.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            result = manager.execute_command("echo test", capture=False)

            assert result == ""
            mock_run.assert_called_once()

    def test_execute_command_failure_raises(self, manager: TerminalManager) -> None:
        """Executing command that fails raises subprocess.CalledProcessError."""
        with patch("intellicrack.core.terminal_manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "failed_command", stderr="error output")

            with pytest.raises(subprocess.CalledProcessError):
                manager.execute_command("failed_command", capture=True)


class TestTerminalManagerScriptExecution:
    """Test script execution in terminal."""

    @pytest.fixture
    def manager_with_terminal(self) -> TerminalManager:
        """Provide terminal manager with registered terminal widget."""
        TerminalManager._instance = None
        manager = TerminalManager()

        mock_terminal_widget = Mock()
        mock_terminal_display = Mock()
        mock_terminal = Mock()
        mock_terminal.terminal_display = mock_terminal_display
        mock_terminal.execute_command = Mock()
        mock_terminal_widget.get_active_session.return_value = ("session_1", mock_terminal)

        manager.register_terminal_widget(mock_terminal_widget)

        return manager

    def test_run_script_in_terminal_executes_command(self, manager_with_terminal: TerminalManager, tmp_path: Path) -> None:
        """Running script in terminal executes command on terminal widget."""
        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        with patch.object(manager_with_terminal, "_resolve_script_path", return_value=script_file):
            with patch.object(manager_with_terminal, "_switch_to_terminal_tab"):
                manager_with_terminal.run_script_in_terminal(str(script_file))

        _session_id, terminal = manager_with_terminal._terminal_widget.get_active_session()
        terminal.execute_command.assert_called_once()

    def test_run_script_in_terminal_switches_to_tab(self, manager_with_terminal: TerminalManager, tmp_path: Path) -> None:
        """Running script in terminal switches to terminal tab."""
        script_file = tmp_path / "test_script.js"
        script_file.write_text("console.log('test')")

        with patch.object(manager_with_terminal, "_resolve_script_path", return_value=script_file):
            with patch.object(manager_with_terminal, "_switch_to_terminal_tab") as mock_switch:
                manager_with_terminal.run_script_in_terminal(str(script_file), switch_to_tab=True)

                mock_switch.assert_called_once()

    def test_run_script_in_terminal_without_widget_logs_error(self, caplog: Any, tmp_path: Path) -> None:
        """Running script without registered terminal widget logs error."""
        TerminalManager._instance = None
        manager = TerminalManager()

        script_file = tmp_path / "test_script.py"
        script_file.write_text("print('test')")

        with patch.object(manager, "_resolve_script_path", return_value=script_file):
            with caplog.at_level(logging.ERROR):
                manager.run_script_in_terminal(str(script_file))

        assert "Terminal widget not registered" in caplog.text


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

        mock_widget = Mock()

        with caplog.at_level(logging.INFO):
            manager.register_terminal_widget(mock_widget)

        assert "Terminal widget registered" in caplog.text

    def test_main_app_registration_logs(self, caplog: Any) -> None:
        """Main app registration logs informational message."""
        TerminalManager._instance = None
        manager = TerminalManager()

        mock_app = Mock()
        mock_app.tabs = Mock()

        with caplog.at_level(logging.INFO):
            manager.set_main_app(mock_app)

        assert "Main app registered" in caplog.text


class TestTerminalManagerIntegration:
    """Integration tests for complete workflows."""

    def test_complete_workflow_register_and_execute(self, tmp_path: Path) -> None:
        """Complete workflow: register components and execute script."""
        TerminalManager._instance = None
        manager = TerminalManager()

        mock_app = Mock()
        mock_tabs = Mock()
        mock_tabs.count.return_value = 2
        mock_tabs.tabText.side_effect = ["Analysis", "Terminal"]
        mock_app.tabs = mock_tabs

        mock_terminal_widget = Mock()
        mock_terminal = Mock()
        mock_terminal.execute_command = Mock()
        mock_terminal_widget.get_active_session.return_value = ("session_1", mock_terminal)

        manager.set_main_app(mock_app)
        manager.register_terminal_widget(mock_terminal_widget)

        script_file = tmp_path / "integration_test.py"
        script_file.write_text("print('integration test')")

        with patch.object(manager, "_resolve_script_path", return_value=script_file):
            manager.run_script_in_terminal(str(script_file), switch_to_tab=True)

        mock_tabs.setCurrentIndex.assert_called_once_with(1)
        mock_terminal.execute_command.assert_called_once()

    def test_multiple_command_executions(self) -> None:
        """Multiple command executions work correctly."""
        TerminalManager._instance = None
        manager = TerminalManager()

        with patch("intellicrack.core.terminal_manager.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.stdout = "output"
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            output1 = manager.execute_command("command1", capture=True)
            output2 = manager.execute_command("command2", capture=True)

            assert output1 == "output"
            assert output2 == "output"
            assert mock_run.call_count == 2
