"""Terminal tab for Intellicrack UI.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Terminal Tab

Main tab containing the terminal session widget for interactive process execution.
"""

import logging
from typing import TYPE_CHECKING, Any

from intellicrack.core.terminal_manager import get_terminal_manager
from intellicrack.handlers.pyqt6_handler import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .base_tab import BaseTab

if TYPE_CHECKING:
    from intellicrack.ui.widgets.terminal_session_widget import TerminalSessionWidget


logger = logging.getLogger(__name__)


class TerminalTab(BaseTab):
    """Terminal tab for interactive process execution.

    Provides:
    - Multi-session terminal management
    - Interactive command/script execution
    - Process control (start, stop, kill)
    - Terminal log export
    - Session status tracking
    """

    def __init__(self, shared_context: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
        """Initialize terminal tab.

        Args:
            shared_context: Optional shared context dictionary with app_context, task_manager, and main_window.
            parent: Optional parent widget.

        """
        if TYPE_CHECKING:
            self.terminal_widget: TerminalSessionWidget | None = None
        else:
            self.terminal_widget: Any = None
        self.status_label: QLabel | None = None
        self.sessions_label: QLabel | None = None
        self.cwd_label: QLabel | None = None

        super().__init__(shared_context, parent)

        logger.info("TerminalTab initialized")

    def setup_content(self) -> None:
        """Set up the terminal tab content."""
        from intellicrack.handlers.pyqt6_handler import QSizePolicy
        from intellicrack.ui.widgets.terminal_session_widget import TerminalSessionWidget as TerminalSessionWidgetClass

        try:
            if old_layout := self.layout():
                while old_layout.count():
                    item = old_layout.takeAt(0)
                    if item is not None:
                        widget = item.widget()
                        if widget is not None:
                            widget.deleteLater()
                old_layout.deleteLater()

            layout = QVBoxLayout(self)
            layout.setContentsMargins(5, 5, 5, 5)
            layout.setSpacing(5)

            toolbar = self._create_toolbar()
            layout.addLayout(toolbar, stretch=0)

            self.terminal_widget = TerminalSessionWidgetClass(self)
            self.terminal_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self.terminal_widget.setMinimumSize(640, 500)
            layout.addWidget(self.terminal_widget, stretch=1)

            status_bar = self._create_status_bar()
            layout.addLayout(status_bar, stretch=0)

            get_terminal_manager().register_terminal_widget(self.terminal_widget)

            self.terminal_widget.session_created.connect(self._on_session_created)
            self.terminal_widget.session_closed.connect(self._on_session_closed)
            self.terminal_widget.active_session_changed.connect(self._on_active_session_changed)

            self._update_status()

            logger.info("Terminal tab content setup complete")

        except Exception as e:
            logger.exception("Terminal tab layout setup failed: %s", e)
            fallback_layout = QVBoxLayout(self)
            error_label = QLabel(f"Terminal initialization failed: {e}")
            fallback_layout.addWidget(error_label)

    def _create_toolbar(self) -> QHBoxLayout:
        """Create toolbar with terminal actions.

        Constructs a horizontal layout containing buttons for terminal operations
        including new session, clear, export log, and kill process controls.

        Returns:
            QHBoxLayout: Configured toolbar layout with action buttons.

        """
        toolbar = QHBoxLayout()

        self.new_session_btn = QPushButton("📟 New Session")
        self.new_session_btn.setToolTip("Create a new terminal session")
        self.new_session_btn.clicked.connect(self.create_new_session)
        toolbar.addWidget(self.new_session_btn)

        self.clear_btn = QPushButton("🗑 Clear")
        self.clear_btn.setToolTip("Clear current terminal")
        self.clear_btn.clicked.connect(self.clear_current_terminal)
        toolbar.addWidget(self.clear_btn)

        self.export_btn = QPushButton(" Export Log")
        self.export_btn.setToolTip("Export terminal log to file")
        self.export_btn.clicked.connect(self.export_terminal_log)
        toolbar.addWidget(self.export_btn)

        self.kill_btn = QPushButton("⛔ Kill Process")
        self.kill_btn.setToolTip("Kill the current running process")
        self.kill_btn.clicked.connect(self.kill_current_process)
        self.kill_btn.setStyleSheet("QPushButton { color: #ff4444; font-weight: bold; }")
        toolbar.addWidget(self.kill_btn)

        toolbar.addStretch()

        return toolbar

    def _create_status_bar(self) -> QHBoxLayout:
        """Create status bar with session info.

        Constructs a horizontal layout containing session count, status, and
        current working directory information labels.

        Returns:
            QHBoxLayout: Configured status bar layout with information labels.

        """
        status_bar = QHBoxLayout()

        self.sessions_label = QLabel("Sessions: 0")
        status_bar.addWidget(self.sessions_label)

        status_bar.addStretch()

        self.status_label = QLabel("Status: Idle")
        status_bar.addWidget(self.status_label)

        status_bar.addStretch()

        self.cwd_label = QLabel("CWD: -")
        status_bar.addWidget(self.cwd_label)

        return status_bar

    def create_new_session(self) -> None:
        """Create a new terminal session."""
        if self.terminal_widget is not None:
            session_id = self.terminal_widget.create_new_session()
            logger.info("Created new terminal session: %s", session_id)
            self._update_status()

    def clear_current_terminal(self) -> None:
        """Clear the current terminal display."""
        if self.terminal_widget is None:
            return

        session_id, terminal = self.terminal_widget.get_active_session()

        if terminal is not None:
            terminal.clear()
            logger.info("Cleared terminal session: %s", session_id)

    def export_terminal_log(self) -> None:
        """Export current terminal log to file."""
        if self.terminal_widget is None:
            return

        _session_id, terminal = self.terminal_widget.get_active_session()

        if terminal is None:
            logger.warning("No active terminal session to export")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Terminal Log",
            "",
            "Text Files (*.txt);;Log Files (*.log);;All Files (*.*)",
        )

        if filename and self.status_label is not None:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(terminal.terminal_display.toPlainText())

                logger.info("Terminal log exported to: %s", filename)

                self.status_label.setText(f"Status: Log exported to {filename}")

            except Exception as e:
                logger.exception("Error exporting terminal log: %s", e)
                self.status_label.setText(f"Status: Export error - {e}")

    def kill_current_process(self) -> None:
        """Kill the currently running process."""
        if self.terminal_widget is None:
            return

        session_id, terminal = self.terminal_widget.get_active_session()

        if terminal is None:
            logger.warning("No active terminal session")
            return

        if self.status_label is None:
            return

        if terminal.is_running():
            terminal.stop_process()
            logger.info("Killed process in session: %s", session_id)
            self.status_label.setText("Status: Process killed")
        else:
            logger.info("No process running in current session")
            self.status_label.setText("Status: No process running")

    def _on_session_created(self, session_id: object) -> None:
        """Handle session created event.

        Updates the status bar when a new terminal session is created.

        Args:
            session_id: The identifier of the newly created session.

        """
        self._update_status()
        logger.info("Session created: %s", session_id)

    def _on_session_closed(self, session_id: object) -> None:
        """Handle session closed event.

        Updates the status bar when a terminal session is closed.

        Args:
            session_id: The identifier of the closed session.

        """
        self._update_status()
        logger.info("Session closed: %s", session_id)

    def _on_active_session_changed(self, session_id: object) -> None:
        """Handle active session changed event.

        Updates the status bar when the active terminal session changes.

        Args:
            session_id: The identifier of the newly active session.

        """
        self._update_status()
        logger.info("Active session changed: %s", session_id)

    def _update_status(self) -> None:
        """Update status bar with current session info."""
        if self.terminal_widget is None:
            return

        sessions = self.terminal_widget.get_all_sessions()
        session_count = len(sessions)

        if self.sessions_label is not None:
            self.sessions_label.setText(f"Sessions: {session_count}")

        _session_id, terminal = self.terminal_widget.get_active_session()

        if self.status_label is None:
            return

        if terminal is not None:
            if terminal.is_running():
                pid = terminal.get_pid()
                self.status_label.setText(f"Status: Running (PID: {pid})")
            else:
                self.status_label.setText("Status: Idle")
        else:
            self.status_label.setText("Status: No session")

    def get_terminal_widget(self) -> Any:
        """Get the terminal session widget.

        Retrieves the TerminalSessionWidget instance used for managing
        multiple terminal sessions and command execution.

        Returns:
            TerminalSessionWidget or None if not initialized.

        """
        return self.terminal_widget
