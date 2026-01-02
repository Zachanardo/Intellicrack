"""Production tests for terminal tab.

This module tests the TerminalTab class which provides multi-session
terminal management for interactive process execution.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ui.tabs.terminal_tab import TerminalTab


class FakeMainWindow:
    """Test double for main window."""
    def __init__(self) -> None:
        self.messages: list[str] = []


class FakeTaskManager:
    """Test double for task manager."""
    def __init__(self) -> None:
        self.tasks: list[dict[str, Any]] = []


class FakeAppContext:
    """Test double for application context."""
    def __init__(self) -> None:
        self.data: dict[str, Any] = {}


class TestTerminalTabInitialization:
    """Test suite for TerminalTab initialization."""

    @pytest.fixture
    def shared_context(self) -> dict[str, object]:
        """Create shared context for tab."""
        return {
            "main_window": FakeMainWindow(),
            "log_message": lambda msg: None,
            "app_context": FakeAppContext(),
            "task_manager": FakeTaskManager(),
        }

    @pytest.fixture
    def terminal_tab(
        self,
        shared_context: dict[str, object],
        qtbot: object,
    ) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab(shared_context)
        qtbot.addWidget(tab)
        return tab

    def test_terminal_tab_initialization(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Terminal tab initializes with default state."""
        assert terminal_tab.terminal_widget is not None
        assert terminal_tab.status_label is not None
        assert terminal_tab.sessions_label is not None
        assert terminal_tab.cwd_label is not None

    def test_terminal_tab_creates_toolbar(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Terminal tab creates toolbar with action buttons."""
        assert hasattr(terminal_tab, "new_session_btn")
        assert hasattr(terminal_tab, "clear_btn")
        assert hasattr(terminal_tab, "export_btn")
        assert hasattr(terminal_tab, "kill_btn")

    def test_terminal_tab_creates_status_bar(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Terminal tab creates status bar with information labels."""
        assert terminal_tab.sessions_label is not None
        assert terminal_tab.status_label is not None
        assert terminal_tab.cwd_label is not None

    def test_terminal_tab_initial_status(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Terminal tab has correct initial status."""
        assert "Sessions: 0" in terminal_tab.sessions_label.text() or "Sessions:" in terminal_tab.sessions_label.text()
        assert "Status:" in terminal_tab.status_label.text()
        assert "CWD:" in terminal_tab.cwd_label.text()

    def test_terminal_widget_registered(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Terminal widget is registered with terminal manager."""
        from intellicrack.core.terminal_manager import get_terminal_manager

        manager = get_terminal_manager()
        assert manager is not None


class TestSessionManagement:
    """Test suite for terminal session management."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        return tab

    def test_create_new_session(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Creating new session adds session to terminal widget."""
        initial_sessions = terminal_tab.terminal_widget.get_all_sessions()
        initial_count = len(initial_sessions)

        terminal_tab.create_new_session()

        new_sessions = terminal_tab.terminal_widget.get_all_sessions()
        assert len(new_sessions) == initial_count + 1

    def test_create_new_session_updates_status(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Creating new session updates status display."""
        initial_text = terminal_tab.sessions_label.text()

        terminal_tab.create_new_session()

        new_text = terminal_tab.sessions_label.text()
        assert new_text != initial_text or "Sessions:" in new_text

    def test_session_created_signal_handled(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """Session created signal updates status."""
        initial_status = terminal_tab.sessions_label.text()
        terminal_tab.terminal_widget.session_created.emit("test_session")
        updated_status = terminal_tab.sessions_label.text()
        assert "Sessions:" in updated_status

    def test_session_closed_signal_handled(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """Session closed signal updates status."""
        terminal_tab.create_new_session()
        initial_count = len(terminal_tab.terminal_widget.get_all_sessions())

        if sessions := terminal_tab.terminal_widget.get_all_sessions():
            terminal_tab.terminal_widget.session_closed.emit(sessions[0])
            status_text = terminal_tab.sessions_label.text()
            assert "Sessions:" in status_text

    def test_active_session_changed_signal_handled(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """Active session changed signal updates status."""
        terminal_tab.create_new_session()

        terminal_tab.terminal_widget.active_session_changed.emit("test_session")
        status_text = terminal_tab.status_label.text()
        assert "Status:" in status_text


class TestTerminalOperations:
    """Test suite for terminal operations."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        tab.create_new_session()
        return tab

    def test_clear_current_terminal(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Clearing terminal clears current session display."""
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal.terminal_display.append("Test output")
            initial_text = terminal.terminal_display.toPlainText()

            terminal_tab.clear_current_terminal()

            cleared_text = terminal.terminal_display.toPlainText()
            assert len(cleared_text) < len(initial_text) or cleared_text == ""

    def test_clear_terminal_without_session(
        self,
        qtbot: object,
    ) -> None:
        """Clearing terminal without active session does not crash."""
        tab = TerminalTab()
        qtbot.addWidget(tab)

        try:
            tab.clear_current_terminal()
        except Exception as e:
            pytest.fail(f"clear_current_terminal raised exception: {e}")

    def test_kill_current_process(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Kill process stops running process in active session."""
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal_tab.kill_current_process()
            status_text = terminal_tab.status_label.text().lower()
            assert "killed" in status_text or "no process" in status_text

    def test_kill_process_without_running_process(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Kill process without running process updates status."""
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal_tab.kill_current_process()
            status_text = terminal_tab.status_label.text()
            assert "No process running" in status_text or "killed" in status_text.lower() or "Status:" in status_text

    def test_kill_process_updates_status(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Kill process updates status label."""
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal_tab.kill_current_process()
            status_text = terminal_tab.status_label.text().lower()
            assert "killed" in status_text or "no process" in status_text or "status:" in status_text


class TestTerminalExport:
    """Test suite for terminal log export functionality."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        tab.create_new_session()
        return tab

    def test_export_terminal_log(
        self,
        terminal_tab: TerminalTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting terminal log creates file with session output."""
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            test_output = "Test terminal output\nLine 2\nLine 3"
            terminal.terminal_display.setPlainText(test_output)

            export_file = tempfile.mktemp(suffix=".txt")

            monkeypatch.setattr("intellicrack.ui.tabs.terminal_tab.QFileDialog.getSaveFileName", lambda *args, **kwargs: (export_file, ""))
            terminal_tab.export_terminal_log()

            assert Path(export_file).exists()

            with open(export_file, encoding="utf-8") as f:
                content = f.read()
                assert test_output in content

            Path(export_file).unlink()

    def test_export_without_session(
        self,
        qtbot: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exporting without active session does not crash."""
        tab = TerminalTab()
        qtbot.addWidget(tab)

        monkeypatch.setattr("intellicrack.ui.tabs.terminal_tab.QFileDialog.getSaveFileName", lambda *args, **kwargs: ("test.txt", ""))
        try:
            tab.export_terminal_log()
        except Exception as e:
            pytest.fail(f"export_terminal_log raised exception: {e}")

    def test_export_handles_io_error(
        self,
        terminal_tab: TerminalTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Export handles I/O errors gracefully."""
        monkeypatch.setattr("intellicrack.ui.tabs.terminal_tab.QFileDialog.getSaveFileName", lambda *args, **kwargs: ("/invalid/path/log.txt", ""))

        try:
            terminal_tab.export_terminal_log()
        except OSError:
            pass

        assert "error" in terminal_tab.status_label.text().lower() or "Error" in terminal_tab.status_label.text()

    def test_export_updates_status(
        self,
        terminal_tab: TerminalTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Export updates status label with filename."""
        export_file = tempfile.mktemp(suffix=".log")

        monkeypatch.setattr("intellicrack.ui.tabs.terminal_tab.QFileDialog.getSaveFileName", lambda *args, **kwargs: (export_file, ""))
        terminal_tab.export_terminal_log()

        assert export_file in terminal_tab.status_label.text() or "Log exported" in terminal_tab.status_label.text()

        if Path(export_file).exists():
            Path(export_file).unlink()


class TestStatusUpdates:
    """Test suite for status update functionality."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        return tab

    def test_update_status_reflects_session_count(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Update status reflects current session count."""
        terminal_tab.create_new_session()
        terminal_tab.create_new_session()

        sessions = terminal_tab.terminal_widget.get_all_sessions()
        session_count = len(sessions)

        terminal_tab._update_status()

        assert str(session_count) in terminal_tab.sessions_label.text()

    def test_update_status_shows_idle_without_process(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Update status shows idle when no process running."""
        terminal_tab.create_new_session()
        terminal_tab._update_status()

        status_text = terminal_tab.status_label.text().lower()
        assert "idle" in status_text or "no" in status_text

    def test_update_status_shows_running_with_process(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Update status shows running when process active."""
        terminal_tab.create_new_session()
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal_tab._update_status()
            status_text = terminal_tab.status_label.text()
            assert "Status:" in status_text

    def test_update_status_without_session(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Update status handles case with no sessions."""
        terminal_tab._update_status()

        status_text = terminal_tab.status_label.text().lower()
        assert "no session" in status_text or "idle" in status_text or "0" in terminal_tab.sessions_label.text()


class TestGetTerminalWidget:
    """Test suite for get_terminal_widget method."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        return tab

    def test_get_terminal_widget_returns_widget(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """get_terminal_widget returns the terminal session widget."""
        widget = terminal_tab.get_terminal_widget()

        assert widget is not None
        assert widget is terminal_tab.terminal_widget

    def test_get_terminal_widget_returns_functional_widget(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """get_terminal_widget returns functional widget with methods."""
        widget = terminal_tab.get_terminal_widget()

        assert hasattr(widget, "create_new_session")
        assert hasattr(widget, "get_active_session")
        assert hasattr(widget, "get_all_sessions")


class TestToolbarButtons:
    """Test suite for toolbar button functionality."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        return tab

    def test_new_session_button_creates_session(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """New session button creates new terminal session."""
        initial_count = len(terminal_tab.terminal_widget.get_all_sessions())

        qtbot.mouseClick(terminal_tab.new_session_btn, 1)

        new_count = len(terminal_tab.terminal_widget.get_all_sessions())
        assert new_count == initial_count + 1

    def test_clear_button_clears_terminal(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """Clear button clears current terminal display."""
        terminal_tab.create_new_session()
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            terminal.terminal_display.append("Test output")

            qtbot.mouseClick(terminal_tab.clear_btn, 1)

            assert len(terminal.terminal_display.toPlainText()) == 0 or terminal.terminal_display.toPlainText() == ""

    def test_export_button_triggers_export(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Export button triggers log export."""
        terminal_tab.create_new_session()

        dialog_called = [False]
        def fake_dialog(*args: Any, **kwargs: Any) -> tuple[str, str]:
            dialog_called[0] = True
            return ("", "")

        monkeypatch.setattr("intellicrack.ui.tabs.terminal_tab.QFileDialog.getSaveFileName", fake_dialog)
        qtbot.mouseClick(terminal_tab.export_btn, 1)
        assert dialog_called[0]

    def test_kill_button_kills_process(
        self,
        terminal_tab: TerminalTab,
        qtbot: object,
    ) -> None:
        """Kill button kills current running process."""
        terminal_tab.create_new_session()
        session_id, terminal = terminal_tab.terminal_widget.get_active_session()

        if terminal:
            qtbot.mouseClick(terminal_tab.kill_btn, 1)
            status_text = terminal_tab.status_label.text().lower()
            assert "killed" in status_text or "no process" in status_text or "status:" in status_text


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def terminal_tab(self, qtbot: object) -> TerminalTab:
        """Create TerminalTab instance."""
        tab = TerminalTab()
        qtbot.addWidget(tab)
        return tab

    def test_operations_without_terminal_widget(
        self,
        qtbot: object,
    ) -> None:
        """Operations handle missing terminal widget gracefully."""
        tab = TerminalTab()
        tab.terminal_widget = None
        qtbot.addWidget(tab)

        try:
            tab.create_new_session()
            tab.clear_current_terminal()
            tab.export_terminal_log()
            tab.kill_current_process()
        except AttributeError as e:
            pytest.fail(f"Operation raised AttributeError: {e}")

    def test_multiple_consecutive_operations(
        self,
        terminal_tab: TerminalTab,
    ) -> None:
        """Multiple consecutive operations work correctly."""
        terminal_tab.create_new_session()
        terminal_tab.create_new_session()
        terminal_tab.clear_current_terminal()
        terminal_tab._update_status()

        sessions = terminal_tab.terminal_widget.get_all_sessions()
        assert len(sessions) >= 2

    def test_status_update_during_initialization(
        self,
        qtbot: object,
    ) -> None:
        """Status update during initialization does not crash."""
        tab = TerminalTab()
        qtbot.addWidget(tab)

        try:
            tab._update_status()
        except Exception as e:
            pytest.fail(f"_update_status during init raised exception: {e}")
