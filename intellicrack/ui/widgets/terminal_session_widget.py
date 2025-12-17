"""Terminal session widget for Intellicrack UI.

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

Terminal Session Widget

Multi-session terminal manager with tabbed interface for managing multiple
concurrent terminal sessions.
"""

import logging
import uuid
from typing import Any, cast

from intellicrack.handlers.pyqt6_handler import QHBoxLayout, QPushButton, QTabWidget, QVBoxLayout, QWidget, pyqtSignal

from .embedded_terminal_widget import EmbeddedTerminalWidget


logger = logging.getLogger(__name__)


class TerminalSessionWidget(QWidget):
    """Manage multiple terminal sessions with tabs.

    Provides:
    - Tabbed interface for multiple terminal sessions
    - Session creation and management
    - Session naming and renaming
    - Active session tracking
    """

    session_created: pyqtSignal = pyqtSignal(str)
    session_closed: pyqtSignal = pyqtSignal(str)
    active_session_changed: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize terminal session widget.

        Args:
            parent: Optional parent widget.

        """
        super().__init__(parent)

        self._sessions: dict[str, Any] = {}
        self._active_session_id: str | None = None

        self._setup_ui()

        logger.info("TerminalSessionWidget initialized")

    def _setup_ui(self) -> None:
        """Set up the UI with tab widget and controls."""
        from intellicrack.handlers.pyqt6_handler import QSizePolicy

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        controls_layout = QHBoxLayout()

        self.new_session_btn = QPushButton("+ New Session")
        self.new_session_btn.clicked.connect(self.create_new_session)
        controls_layout.addWidget(self.new_session_btn)

        self.close_session_btn = QPushButton("✖ Close Session")
        self.close_session_btn.clicked.connect(self.close_current_session)
        controls_layout.addWidget(self.close_session_btn)

        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.tab_widget = QTabWidget(self)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab_at_index)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        self.tab_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tab_widget.setMinimumSize(620, 450)

        layout.addWidget(self.tab_widget, stretch=1)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumSize(620, 480)

        self.create_new_session()

    def create_new_session(self, name: str | None = None) -> str:
        """Create new terminal session.

        Args:
            name: Optional session name. If not provided, auto-generates one.

        Returns:
            Session ID as a UUID string.

        """
        session_id = str(uuid.uuid4())

        terminal = EmbeddedTerminalWidget(self)

        if name is None:
            session_count = len(self._sessions) + 1
            name = f"Terminal {session_count}"

        self._sessions[session_id] = {
            "widget": terminal,
            "name": name,
        }

        index = self.tab_widget.addTab(terminal, name)
        self.tab_widget.setCurrentIndex(index)

        terminal.process_started.connect(lambda pid: self._on_process_started(session_id, pid))
        terminal.process_finished.connect(lambda pid, code: self._on_process_finished(session_id, pid, code))

        self._active_session_id = session_id
        self.session_created.emit(session_id)

        logger.info("Created new terminal session: %s (%s)", session_id, name)

        return session_id

    def close_session(self, session_id: str) -> None:
        """Close specified session.

        Args:
            session_id: ID of session to close.

        """
        if session_id not in self._sessions:
            logger.warning("Session %s not found", session_id)
            return

        session = self._sessions[session_id]
        terminal = session["widget"]

        if terminal.is_running():
            terminal.stop_process()

        for i in range(self.tab_widget.count()):
            if self.tab_widget.widget(i) == terminal:
                self.tab_widget.removeTab(i)
                break

        del self._sessions[session_id]

        if self._active_session_id == session_id:
            self._active_session_id = None

        self.session_closed.emit(session_id)

        logger.info("Closed terminal session: %s", session_id)

        if len(self._sessions) == 0:
            self.create_new_session()

    def close_current_session(self) -> None:
        """Close the currently active session."""
        if self._active_session_id:
            self.close_session(self._active_session_id)

    def _close_tab_at_index(self, index: int) -> None:
        """Close tab at specified index.

        Args:
            index: Tab index to close.

        """
        widget = self.tab_widget.widget(index)

        for session_id, session_data in self._sessions.items():
            if session_data["widget"] == widget:
                self.close_session(session_id)
                break

    def _on_tab_changed(self, index: int) -> None:
        """Handle tab change event.

        Args:
            index: Index of the newly selected tab.

        """
        if index < 0:
            self._active_session_id = None
            return

        widget = self.tab_widget.widget(index)

        for session_id, session_data in self._sessions.items():
            if session_data["widget"] == widget:
                self._active_session_id = session_id
                self.active_session_changed.emit(session_id)
                terminal_widget = session_data["widget"]
                terminal_widget.terminal_display.setFocus()
                break

    def get_active_session(self) -> tuple[str | None, EmbeddedTerminalWidget | None]:
        """Get currently active terminal session.

        Returns:
            Tuple of (session_id, EmbeddedTerminalWidget) or (None, None).

        """
        if self._active_session_id and self._active_session_id in self._sessions:
            session = self._sessions[self._active_session_id]
            return (self._active_session_id, session["widget"])

        return (None, None)

    def get_session(self, session_id: str) -> EmbeddedTerminalWidget | None:
        """Get specific session by ID.

        Args:
            session_id: ID of session to retrieve.

        Returns:
            EmbeddedTerminalWidget instance or None if not found.

        """
        if session_id in self._sessions:
            return cast("EmbeddedTerminalWidget", self._sessions[session_id]["widget"])

        return None

    def switch_to_session(self, session_id: str) -> None:
        """Switch to specified session tab.

        Args:
            session_id: ID of session to switch to.

        """
        if session_id not in self._sessions:
            logger.warning("Session %s not found", session_id)
            return

        session = self._sessions[session_id]
        widget = session["widget"]

        for i in range(self.tab_widget.count()):
            if self.tab_widget.widget(i) == widget:
                self.tab_widget.setCurrentIndex(i)
                widget.terminal_display.setFocus()
                break

    def rename_session(self, session_id: str, new_name: str) -> None:
        """Rename a session.

        Args:
            session_id: ID of session to rename.
            new_name: New name for the session.

        """
        if session_id not in self._sessions:
            logger.warning("Session %s not found", session_id)
            return

        self._sessions[session_id]["name"] = new_name

        session = self._sessions[session_id]
        widget = session["widget"]

        for i in range(self.tab_widget.count()):
            if self.tab_widget.widget(i) == widget:
                self.tab_widget.setTabText(i, new_name)
                break

        logger.info("Renamed session %s to: %s", session_id, new_name)

    def get_all_sessions(self) -> dict[str, Any]:
        """Get all active sessions.

        Returns:
            Dictionary of session_id to session data mapping.

        """
        return self._sessions.copy()

    def _on_process_started(self, session_id: str, pid: int) -> None:
        """Handle process started in session.

        Args:
            session_id: ID of session where process started.
            pid: Process ID of the started process.

        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            name = session["name"]

            widget = session["widget"]
            for i in range(self.tab_widget.count()):
                if self.tab_widget.widget(i) == widget:
                    self.tab_widget.setTabText(i, f"{name} [PID:{pid}]")
                    break

    def _on_process_finished(self, session_id: str, pid: int, exit_code: int) -> None:
        """Handle process finished in session.

        Args:
            session_id: ID of session where process finished.
            pid: Process ID of the finished process.
            exit_code: Exit code returned by the process.

        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            name = session["name"]

            widget = session["widget"]
            for i in range(self.tab_widget.count()):
                if self.tab_widget.widget(i) == widget:
                    self.tab_widget.setTabText(i, name)
                    break
