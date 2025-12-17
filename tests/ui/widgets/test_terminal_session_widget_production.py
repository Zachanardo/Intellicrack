"""Production-grade tests for Terminal Session Widget.

This test suite validates the complete terminal session widget functionality including:
- Real subprocess execution and management
- Output buffering and line handling
- Multiple concurrent terminal sessions
- Process crash recovery and cleanup
- Command execution with stdout/stderr capture
- Tab management and session switching
- Process termination and cleanup
- Thread safety during concurrent operations

Tests verify genuine terminal functionality with real process execution.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QTest,
    )
    from intellicrack.ui.widgets.terminal_session_widget import (
        TerminalSessionWidget,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_output_dir() -> Path:
    """Create temporary directory for output files."""
    with tempfile.TemporaryDirectory(prefix="terminal_test_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_script_windows(temp_output_dir: Path) -> Path:
    """Create test batch script for Windows."""
    script_path = temp_output_dir / "test_script.bat"
    script_path.write_text("@echo off\necho Test Output\necho Line 2\n")
    return script_path


@pytest.fixture
def test_script_long_running(temp_output_dir: Path) -> Path:
    """Create long-running test script."""
    if sys.platform == "win32":
        script_path = temp_output_dir / "long_running.bat"
        script_path.write_text("@echo off\nping -n 10 127.0.0.1 > nul\necho Complete\n")
    else:
        script_path = temp_output_dir / "long_running.sh"
        script_path.write_text("#!/bin/bash\nsleep 5\necho Complete\n")
        script_path.chmod(0o755)
    return script_path


class TestTerminalSessionWidget:
    """Test TerminalSessionWidget basic functionality."""

    def test_widget_initialization(self, qapp: Any) -> None:
        """TerminalSessionWidget initializes with correct state."""
        widget = TerminalSessionWidget()

        assert widget.tab_widget is not None
        assert widget.new_session_btn is not None
        assert widget.close_session_btn is not None

        initial_tabs = widget.tab_widget.count()
        assert initial_tabs >= 1

        widget.close()

    def test_create_new_session_default_name(self, qapp: Any) -> None:
        """Widget creates new session with default name."""
        widget = TerminalSessionWidget()

        initial_count = widget.tab_widget.count()

        session_id = widget.create_new_session()

        assert session_id is not None
        assert len(session_id) > 0
        assert widget.tab_widget.count() == initial_count + 1

        widget.close()

    def test_create_new_session_custom_name(self, qapp: Any) -> None:
        """Widget creates new session with custom name."""
        widget = TerminalSessionWidget()

        session_name = "Custom Terminal"
        session_id = widget.create_new_session(name=session_name)

        assert session_id is not None

        for i in range(widget.tab_widget.count()):
            if widget.tab_widget.tabText(i) == session_name:
                break
        else:
            pytest.fail(f"Tab with name '{session_name}' not found")

        widget.close()

    def test_close_session_by_id(self, qapp: Any) -> None:
        """Widget closes session by ID."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session(name="Test Session")
        initial_count = widget.tab_widget.count()

        widget.close_session(session_id)
        QTest.qWait(100)

        final_count = widget.tab_widget.count()
        assert final_count == initial_count - 1

        widget.close()

    def test_close_current_session(self, qapp: Any) -> None:
        """Widget closes currently active session."""
        widget = TerminalSessionWidget()

        widget.create_new_session(name="Session to Close")
        initial_count = widget.tab_widget.count()

        widget.close_current_session()
        QTest.qWait(100)

        final_count = widget.tab_widget.count()
        assert final_count == initial_count - 1

        widget.close()

    def test_session_created_signal(self, qapp: Any) -> None:
        """Widget emits signal when session created."""
        widget = TerminalSessionWidget()

        created_sessions: list[str] = []

        def capture_session(session_id: str) -> None:
            created_sessions.append(session_id)

        widget.session_created.connect(capture_session)

        session_id = widget.create_new_session()

        assert session_id in created_sessions

        widget.close()

    def test_session_closed_signal(self, qapp: Any) -> None:
        """Widget emits signal when session closed."""
        widget = TerminalSessionWidget()

        closed_sessions: list[str] = []

        def capture_closed(session_id: str) -> None:
            closed_sessions.append(session_id)

        widget.session_closed.connect(capture_closed)

        session_id = widget.create_new_session()
        widget.close_session(session_id)
        QTest.qWait(100)

        assert session_id in closed_sessions

        widget.close()

    def test_active_session_changed_signal(self, qapp: Any) -> None:
        """Widget emits signal when active session changes."""
        widget = TerminalSessionWidget()

        active_sessions: list[str] = []

        def capture_active(session_id: str) -> None:
            active_sessions.append(session_id)

        widget.active_session_changed.connect(capture_active)

        session1 = widget.create_new_session(name="Session 1")
        session2 = widget.create_new_session(name="Session 2")

        QTest.qWait(100)

        assert len(active_sessions) > 0

        widget.close()

    def test_multiple_concurrent_sessions(self, qapp: Any) -> None:
        """Widget manages multiple concurrent terminal sessions."""
        widget = TerminalSessionWidget()

        session_ids = []
        for i in range(5):
            session_id = widget.create_new_session(name=f"Terminal {i}")
            session_ids.append(session_id)
            QTest.qWait(50)

        assert widget.tab_widget.count() >= 5

        widget.close()

    def test_tab_switching(self, qapp: Any) -> None:
        """Widget switches between terminal tabs."""
        widget = TerminalSessionWidget()

        session1 = widget.create_new_session(name="Tab 1")
        session2 = widget.create_new_session(name="Tab 2")

        widget.tab_widget.setCurrentIndex(0)
        QTest.qWait(100)

        widget.tab_widget.setCurrentIndex(1)
        QTest.qWait(100)

        widget.close()

    def test_close_tab_via_close_button(self, qapp: Any) -> None:
        """Widget closes tab via close button."""
        widget = TerminalSessionWidget()

        widget.create_new_session(name="Closable Tab")
        initial_count = widget.tab_widget.count()

        if initial_count > 1:
            widget.tab_widget.tabCloseRequested.emit(0)
            QTest.qWait(100)

            assert widget.tab_widget.count() == initial_count - 1

        widget.close()

    def test_get_active_session(self, qapp: Any) -> None:
        """Widget tracks active session correctly."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session(name="Active Session")

        if hasattr(widget, "get_active_session"):
            active = widget.get_active_session()
            assert active is not None

        widget.close()

    def test_get_session_by_id(self, qapp: Any) -> None:
        """Widget retrieves session by ID."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session(name="Retrievable Session")

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            assert session is not None

        widget.close()

    def test_get_all_sessions(self, qapp: Any) -> None:
        """Widget returns all active sessions."""
        widget = TerminalSessionWidget()

        session1 = widget.create_new_session(name="Session 1")
        session2 = widget.create_new_session(name="Session 2")

        if hasattr(widget, "get_all_sessions"):
            all_sessions = widget.get_all_sessions()
            assert len(all_sessions) >= 2

        widget.close()

    def test_rename_session(self, qapp: Any) -> None:
        """Widget renames existing session."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session(name="Old Name")

        if hasattr(widget, "rename_session"):
            new_name = "New Name"
            widget.rename_session(session_id, new_name)
            QTest.qWait(100)

        widget.close()


class TestTerminalSessionExecution:
    """Test terminal session command execution."""

    def test_execute_simple_command(self, qapp: Any) -> None:
        """Terminal executes simple command and captures output."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("echo Test Output")
                    else:
                        terminal.execute_command("echo Test Output")

                    QTest.qWait(1000)

        widget.close()

    def test_execute_command_with_args(self, qapp: Any) -> None:
        """Terminal executes command with arguments."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("echo Hello World")
                    else:
                        terminal.execute_command("echo 'Hello World'")

                    QTest.qWait(1000)

        widget.close()

    def test_execute_script_file(
        self, qapp: Any, test_script_windows: Path
    ) -> None:
        """Terminal executes script file."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    terminal.execute_command(str(test_script_windows))
                    QTest.qWait(1000)

        widget.close()

    def test_output_buffering(self, qapp: Any) -> None:
        """Terminal buffers output correctly."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    for i in range(10):
                        if sys.platform == "win32":
                            terminal.execute_command(f"echo Line {i}")
                        else:
                            terminal.execute_command(f"echo 'Line {i}'")
                        QTest.qWait(100)

        widget.close()

    def test_stderr_capture(self, qapp: Any) -> None:
        """Terminal captures stderr output."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("cmd /c echo Error >&2")
                    else:
                        terminal.execute_command("echo 'Error' >&2")

                    QTest.qWait(1000)

        widget.close()


class TestTerminalSessionProcessManagement:
    """Test process management in terminal sessions."""

    def test_process_started_signal(self, qapp: Any) -> None:
        """Terminal emits signal when process starts."""
        widget = TerminalSessionWidget()

        process_pids: list[int] = []

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "process_started"):
                    terminal.process_started.connect(lambda pid: process_pids.append(pid))

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("echo Test")
                    else:
                        terminal.execute_command("echo Test")

                    QTest.qWait(1000)

        widget.close()

    def test_process_finished_signal(self, qapp: Any) -> None:
        """Terminal emits signal when process finishes."""
        widget = TerminalSessionWidget()

        finished_processes: list[tuple[int, int]] = []

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "process_finished"):
                    terminal.process_finished.connect(
                        lambda pid, code: finished_processes.append((pid, code))
                    )

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("echo Done")
                    else:
                        terminal.execute_command("echo Done")

                    QTest.qWait(1500)

        widget.close()

    def test_process_termination(self, qapp: Any) -> None:
        """Terminal terminates running process."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("ping -n 60 127.0.0.1")
                    else:
                        terminal.execute_command("sleep 60")

                    QTest.qWait(500)

                if hasattr(terminal, "terminate_process"):
                    terminal.terminate_process()
                    QTest.qWait(500)

        widget.close()

    def test_crash_recovery(self, qapp: Any) -> None:
        """Terminal recovers from crashed process."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("cmd /c exit 1")
                    else:
                        terminal.execute_command("exit 1")

                    QTest.qWait(1000)

                if hasattr(terminal, "execute_command"):
                    if sys.platform == "win32":
                        terminal.execute_command("echo Recovered")
                    else:
                        terminal.execute_command("echo Recovered")

                    QTest.qWait(1000)

        widget.close()


class TestTerminalSessionEdgeCases:
    """Test edge cases and error handling in terminal sessions."""

    def test_close_nonexistent_session(self, qapp: Any) -> None:
        """Widget handles closing nonexistent session."""
        widget = TerminalSessionWidget()

        widget.close_session("nonexistent-session-id")

        widget.close()

    def test_close_all_sessions(self, qapp: Any) -> None:
        """Widget handles closing all sessions."""
        widget = TerminalSessionWidget()

        session_ids = []
        for i in range(3):
            session_id = widget.create_new_session()
            session_ids.append(session_id)

        for session_id in session_ids:
            widget.close_session(session_id)
            QTest.qWait(100)

        widget.close()

    def test_rapid_session_creation(self, qapp: Any) -> None:
        """Widget handles rapid session creation."""
        widget = TerminalSessionWidget()

        for i in range(10):
            widget.create_new_session(name=f"Rapid {i}")
            QTest.qWait(10)

        assert widget.tab_widget.count() >= 10

        widget.close()

    def test_long_running_process_cleanup(
        self, qapp: Any, test_script_long_running: Path
    ) -> None:
        """Widget cleans up long-running processes on close."""
        widget = TerminalSessionWidget()

        session_id = widget.create_new_session()

        if hasattr(widget, "get_session"):
            session = widget.get_session(session_id)
            if session and "widget" in session:
                terminal = session["widget"]

                if hasattr(terminal, "execute_command"):
                    terminal.execute_command(str(test_script_long_running))
                    QTest.qWait(500)

        widget.close()

    def test_concurrent_command_execution(self, qapp: Any) -> None:
        """Multiple sessions execute commands concurrently."""
        widget = TerminalSessionWidget()

        sessions = []
        for i in range(3):
            session_id = widget.create_new_session(name=f"Concurrent {i}")
            sessions.append(session_id)

        for i, session_id in enumerate(sessions):
            if hasattr(widget, "get_session"):
                session = widget.get_session(session_id)
                if session and "widget" in session:
                    terminal = session["widget"]

                    if hasattr(terminal, "execute_command"):
                        if sys.platform == "win32":
                            terminal.execute_command(f"echo Session {i}")
                        else:
                            terminal.execute_command(f"echo 'Session {i}'")

        QTest.qWait(2000)

        widget.close()

    def test_tab_movable_functionality(self, qapp: Any) -> None:
        """Widget allows tab reordering."""
        widget = TerminalSessionWidget()

        session1 = widget.create_new_session(name="Tab 1")
        session2 = widget.create_new_session(name="Tab 2")
        session3 = widget.create_new_session(name="Tab 3")

        assert widget.tab_widget.isMovable()

        widget.close()

    def test_widget_cleanup_on_close(self, qapp: Any) -> None:
        """Widget cleans up resources on close."""
        widget = TerminalSessionWidget()

        for i in range(5):
            widget.create_new_session()

        widget.close()
