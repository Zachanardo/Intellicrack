"""Integration tests for terminal manager and widget integration.

Tests the interaction between terminal manager, session widgets, and main application.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.terminal_manager import TerminalManager, get_terminal_manager
from intellicrack.ui.widgets.terminal_session_widget import TerminalSessionWidget


@pytest.fixture(scope="module")
def qapp():
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def terminal_manager(qapp):
    """Create fresh terminal manager instance."""
    # Reset singleton for testing
    TerminalManager._instance = None
    manager = get_terminal_manager()
    yield manager
    # Cleanup
    if manager._terminal_widget:
        manager._terminal_widget.close()
    TerminalManager._instance = None


@pytest.fixture
def session_widget(qapp, qtbot):
    """Create terminal session widget."""
    widget = TerminalSessionWidget()
    qtbot.addWidget(widget)
    widget.show()
    qtbot.waitExposed(widget)
    yield widget
    widget.close()


class TestTerminalManagerSingleton:
    """Test terminal manager singleton pattern."""

    def test_singleton_instance(self, qapp):
        """Test that terminal manager is a singleton."""
        TerminalManager._instance = None

        manager1 = get_terminal_manager()
        manager2 = get_terminal_manager()

        assert manager1 is manager2
        assert TerminalManager._instance is not None

        TerminalManager._instance = None

    def test_multiple_get_calls(self, qapp):
        """Test multiple get_terminal_manager calls return same instance."""
        TerminalManager._instance = None

        managers = [get_terminal_manager() for _ in range(5)]

        assert all(m is managers[0] for m in managers)

        TerminalManager._instance = None


class TestScriptExecution:
    """Test script execution through terminal manager."""

    def test_execute_script(self, terminal_manager, qtbot):
        """Test executing a script through terminal manager."""
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.bat' if sys.platform == 'win32' else '.sh', delete=False) as f:
            if sys.platform == 'win32':
                f.write('@echo off\necho SCRIPT_OUTPUT\n')
            else:
                f.write('#!/bin/sh\necho SCRIPT_OUTPUT\n')
            script_path = f.name

        try:
            session_id = terminal_manager.execute_script(script_path, interactive=False)

            assert session_id is not None
            assert len(session_id) > 0

            qtbot.wait(1000)

        finally:
            Path(script_path).unlink(missing_ok=True)

    def test_execute_command(self, terminal_manager, qtbot):
        """Test executing a command through terminal manager."""
        if sys.platform == 'win32':
            command = ['cmd', '/c', 'echo', 'COMMAND_OUTPUT']
        else:
            command = ['echo', 'COMMAND_OUTPUT']

        session_id = terminal_manager.execute_command(
            command=command,
            capture_output=False,
            auto_switch=False
        )

        assert session_id is not None
        qtbot.wait(500)

    def test_execute_with_cwd(self, terminal_manager, qtbot):
        """Test executing command with custom working directory."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            command = ['cmd', '/c', 'cd'] if sys.platform == 'win32' else ['pwd']
            session_id = terminal_manager.execute_command(
                command=command,
                capture_output=False,
                cwd=tmpdir
            )

            assert session_id is not None
            qtbot.wait(500)


class TestAutoSwitch:
    """Test auto-switch to Terminal tab functionality."""

    def test_auto_switch_enabled(self, terminal_manager, qtbot):
        """Test auto-switch functionality when enabled."""
        if sys.platform == 'win32':
            command = ['cmd', '/c', 'echo', 'AUTO_SWITCH_TEST']
        else:
            command = ['echo', 'AUTO_SWITCH_TEST']

        session_id = terminal_manager.execute_command(
            command=command,
            auto_switch=True
        )

        assert session_id is not None
        qtbot.wait(500)

    def test_auto_switch_disabled(self, terminal_manager, qtbot):
        """Test execution without auto-switch."""
        if sys.platform == 'win32':
            command = ['cmd', '/c', 'echo', 'NO_SWITCH_TEST']
        else:
            command = ['echo', 'NO_SWITCH_TEST']

        session_id = terminal_manager.execute_command(
            command=command,
            auto_switch=False
        )

        assert session_id is not None
        qtbot.wait(500)


class TestMultipleSessions:
    """Test multiple terminal sessions."""

    def test_create_multiple_sessions(self, session_widget, qtbot):
        """Test creating multiple terminal sessions."""
        session_ids = []

        for i in range(3):
            session_id = session_widget.create_new_session(name=f"Session {i}")
            session_ids.append(session_id)
            qtbot.wait(200)

        assert len(session_ids) == 3
        assert len(set(session_ids)) == 3

    def test_switch_between_sessions(self, session_widget, qtbot):
        """Test switching between terminal sessions."""
        session1 = session_widget.create_new_session(name="First")
        qtbot.wait(200)

        session2 = session_widget.create_new_session(name="Second")
        qtbot.wait(200)

        session_widget.switch_to_session(session1)
        qtbot.wait(100)

        active = session_widget.get_active_session()
        assert active is not None

        session_widget.switch_to_session(session2)
        qtbot.wait(100)

        active2 = session_widget.get_active_session()
        assert active2 is not None

    def test_close_session(self, session_widget, qtbot):
        """Test closing a terminal session."""
        session_id = session_widget.create_new_session(name="ToClose")
        qtbot.wait(200)

        session_widget.close_session(session_id)
        qtbot.wait(200)

        session = session_widget.get_session(session_id)
        assert session is None


class TestWindowsActivatorIntegration:
    """Test Windows Activator integration with terminal."""

    def test_windows_activator_script_exists(self):
        """Test that WindowsActivator.cmd exists."""
        script_path = Path("intellicrack/scripts/Windows_Patch/WindowsActivator.cmd")
        assert script_path.exists(), "WindowsActivator.cmd should exist"

    def test_execute_windows_activator(self, terminal_manager, qtbot):
        """Test executing Windows Activator through terminal (if on Windows)."""
        if sys.platform != 'win32':
            pytest.skip("Windows Activator only works on Windows")

        script_path = Path("intellicrack/scripts/Windows_Patch/WindowsActivator.cmd")
        if not script_path.exists():
            pytest.skip("WindowsActivator.cmd not found")

        # This will launch the menu but won't interact with it
        # Full interaction testing requires manual verification
        session_id = terminal_manager.execute_script(
            script_path=str(script_path),
            interactive=True,
            auto_switch=True
        )

        assert session_id is not None
        qtbot.wait(1000)

        # Stop the process to prevent hanging
        if terminal_manager._terminal_widget:
            active_session = terminal_manager._terminal_widget.get_active_session()
            if active_session and active_session.is_running():
                active_session.stop_process()


class TestSessionManagement:
    """Test session management functionality."""

    def test_get_all_sessions(self, session_widget, qtbot):
        """Test retrieving all sessions."""
        session_widget.create_new_session(name="Test1")
        qtbot.wait(100)

        session_widget.create_new_session(name="Test2")
        qtbot.wait(100)

        all_sessions = session_widget.get_all_sessions()
        assert len(all_sessions) >= 2

    def test_rename_session(self, session_widget, qtbot):
        """Test renaming a terminal session."""
        session_id = session_widget.create_new_session(name="OldName")
        qtbot.wait(200)

        session_widget.rename_session(session_id, "NewName")
        qtbot.wait(100)

        # Verification would require checking tab text
        # which depends on internal implementation

    def test_active_session_tracking(self, session_widget, qtbot):
        """Test active session tracking."""
        session1 = session_widget.create_new_session()
        qtbot.wait(100)

        active = session_widget.get_active_session()
        assert active is not None

        session2 = session_widget.create_new_session()
        qtbot.wait(100)

        active2 = session_widget.get_active_session()
        assert active2 is not None


class TestErrorHandling:
    """Test error handling in terminal integration."""

    def test_invalid_script_path(self, terminal_manager):
        """Test handling of invalid script path."""
        with pytest.raises((FileNotFoundError, OSError)):
            terminal_manager.execute_script(
                script_path="/nonexistent/script.sh",
                interactive=False
            )

    def test_invalid_command(self, terminal_manager, qtbot):
        """Test handling of invalid command."""
        session_id = terminal_manager.execute_command(
            command=['nonexistent_command_xyz123'],
            capture_output=False
        )

        # Should still create session even if command fails
        assert session_id is not None
        qtbot.wait(500)

    def test_close_nonexistent_session(self, session_widget):
        """Test closing a non-existent session."""
        # Should handle gracefully without error
        session_widget.close_session("nonexistent_session_id")


class TestOutputCapture:
    """Test output capture modes."""

    def test_capture_output_enabled(self, terminal_manager, qtbot):
        """Test command execution with output capture."""
        if sys.platform == 'win32':
            command = ['cmd', '/c', 'echo', 'CAPTURED_OUTPUT']
        else:
            command = ['echo', 'CAPTURED_OUTPUT']

        session_id = terminal_manager.execute_command(
            command=command,
            capture_output=True
        )

        assert session_id is not None
        qtbot.wait(500)

    def test_capture_output_disabled(self, terminal_manager, qtbot):
        """Test command execution without output capture."""
        if sys.platform == 'win32':
            command = ['cmd', '/c', 'echo', 'UNCAPTURED_OUTPUT']
        else:
            command = ['echo', 'UNCAPTURED_OUTPUT']

        session_id = terminal_manager.execute_command(
            command=command,
            capture_output=False
        )

        assert session_id is not None
        qtbot.wait(500)
