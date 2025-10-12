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

from intellicrack.core.terminal_manager import get_terminal_manager
from intellicrack.handlers.pyqt6_handler import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)
from intellicrack.ui.widgets import TerminalSessionWidget

from .base_tab import BaseTab

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

    def __init__(self, shared_context=None, parent=None):
        """Initialize terminal tab."""
        self.terminal_widget = None
        self.status_label = None
        self.sessions_label = None
        self.cwd_label = None

        super().__init__(shared_context, parent)

        logger.info("TerminalTab initialized")

    def setup_content(self):
        """Setup the terminal tab content."""
        from intellicrack.handlers.pyqt6_handler import QSizePolicy

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        toolbar = self._create_toolbar()
        layout.addLayout(toolbar, stretch=0)

        self.terminal_widget = TerminalSessionWidget(self)
        self.terminal_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.terminal_widget, stretch=1)

        status_bar = self._create_status_bar()
        layout.addLayout(status_bar, stretch=0)

        get_terminal_manager().register_terminal_widget(self.terminal_widget)

        self.terminal_widget.session_created.connect(self._on_session_created)
        self.terminal_widget.session_closed.connect(self._on_session_closed)
        self.terminal_widget.active_session_changed.connect(self._on_active_session_changed)

        self._update_status()

        logger.info("Terminal tab content setup complete")

    def _create_toolbar(self):
        """Create toolbar with terminal actions."""
        toolbar = QHBoxLayout()

        self.new_session_btn = QPushButton("📟 New Session")
        self.new_session_btn.setToolTip("Create a new terminal session")
        self.new_session_btn.clicked.connect(self.create_new_session)
        toolbar.addWidget(self.new_session_btn)

        self.clear_btn = QPushButton("🗑 Clear")
        self.clear_btn.setToolTip("Clear current terminal")
        self.clear_btn.clicked.connect(self.clear_current_terminal)
        toolbar.addWidget(self.clear_btn)

        self.export_btn = QPushButton("💾 Export Log")
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

    def _create_status_bar(self):
        """Create status bar with session info."""
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

    def create_new_session(self):
        """Create a new terminal session."""
        if self.terminal_widget:
            session_id = self.terminal_widget.create_new_session()
            logger.info(f"Created new terminal session: {session_id}")
            self._update_status()

    def clear_current_terminal(self):
        """Clear the current terminal display."""
        if not self.terminal_widget:
            return

        session_id, terminal = self.terminal_widget.get_active_session()

        if terminal:
            terminal.clear()
            logger.info(f"Cleared terminal session: {session_id}")

    def export_terminal_log(self):
        """Export current terminal log to file."""
        if not self.terminal_widget:
            return

        session_id, terminal = self.terminal_widget.get_active_session()

        if not terminal:
            logger.warning("No active terminal session to export")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Export Terminal Log", "", "Text Files (*.txt);;Log Files (*.log);;All Files (*.*)")

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(terminal.terminal_display.toPlainText())

                logger.info(f"Terminal log exported to: {filename}")

                self.status_label.setText(f"Status: Log exported to {filename}")

            except Exception as e:
                logger.error(f"Error exporting terminal log: {e}")
                self.status_label.setText(f"Status: Export error - {e}")

    def kill_current_process(self):
        """Kill the currently running process."""
        if not self.terminal_widget:
            return

        session_id, terminal = self.terminal_widget.get_active_session()

        if not terminal:
            logger.warning("No active terminal session")
            return

        if terminal.is_running():
            terminal.stop_process()
            logger.info(f"Killed process in session: {session_id}")
            self.status_label.setText("Status: Process killed")
        else:
            logger.info("No process running in current session")
            self.status_label.setText("Status: No process running")

    def _on_session_created(self, session_id):
        """Handle session created event."""
        self._update_status()
        logger.info(f"Session created: {session_id}")

    def _on_session_closed(self, session_id):
        """Handle session closed event."""
        self._update_status()
        logger.info(f"Session closed: {session_id}")

    def _on_active_session_changed(self, session_id):
        """Handle active session changed event."""
        self._update_status()
        logger.info(f"Active session changed: {session_id}")

    def _update_status(self):
        """Update status bar with current session info."""
        if not self.terminal_widget:
            return

        sessions = self.terminal_widget.get_all_sessions()
        session_count = len(sessions)

        self.sessions_label.setText(f"Sessions: {session_count}")

        session_id, terminal = self.terminal_widget.get_active_session()

        if terminal:
            if terminal.is_running():
                pid = terminal.get_pid()
                self.status_label.setText(f"Status: Running (PID: {pid})")
            else:
                self.status_label.setText("Status: Idle")
        else:
            self.status_label.setText("Status: No session")

    def get_terminal_widget(self):
        """Get the terminal session widget.

        Returns:
            TerminalSessionWidget

        """
        return self.terminal_widget
