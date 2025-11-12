"""UI Manager for Intellicrack.

This module provides a centralized UI manager for creating and managing the main
application window and its components.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging

from intellicrack.handlers.pyqt6_handler import (
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .tabs.ai_assistant_tab import AIAssistantTab
from .tabs.analysis_tab import AnalysisTab
from .tabs.dashboard_tab import DashboardTab
from .tabs.exploitation_tab import ExploitationTab
from .tabs.settings_tab import SettingsTab
from .tabs.terminal_tab import TerminalTab
from .tabs.tools_tab import ToolsTab
from .tabs.workspace_tab import WorkspaceTab
from .theme_manager import get_theme_manager
from ..utils.logger import log_all_methods

logger = logging.getLogger(__name__)


@log_all_methods
class UIManager:
    """Manages the creation and layout of the main UI components."""

    def __init__(self, main_window) -> None:
        """Initialize the UI Manager.

        Args:
            main_window: The main application window.

        """
        self.logger = logger
        self.main_window = main_window
        self.theme_manager = get_theme_manager()

    def create_main_layout(self) -> None:
        """Create the main UI layout."""
        self.main_window.central_widget = QWidget()
        self.main_window.setCentralWidget(self.main_window.central_widget)
        self.main_window.main_layout = QVBoxLayout(self.main_window.central_widget)

        self.main_window.create_toolbar()

        self.main_window.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_window.main_layout.addWidget(self.main_window.main_splitter)

    def setup_tabs_and_themes(self) -> None:
        """Set up the tab widget and apply themes."""
        self.main_window.tabs = QTabWidget()
        self.main_window.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.main_window.tabs.setTabsClosable(False)

        self.theme_manager.set_theme(self.theme_manager.get_current_theme())

        self.main_window.main_splitter.addWidget(self.main_window.tabs)

    def create_output_panel(self) -> None:
        """Create the output panel."""
        self.main_window.output_panel = QWidget()
        self.main_window.output_layout = QVBoxLayout(self.main_window.output_panel)

        self.main_window.output = QTextEdit()
        self.main_window.output.setReadOnly(True)

        self.main_window.raw_console_output = QPlainTextEdit()
        self.main_window.raw_console_output.setReadOnly(True)
        self.main_window.raw_console_output.setMaximumBlockCount(1000)

        self.main_window.clear_output_btn = QPushButton("Clear Output")
        self.main_window.clear_output_btn.clicked.connect(self.main_window.clear_output)

        self.main_window.output_layout.addWidget(QLabel("<b>Output</b>"))
        self.main_window.output_layout.addWidget(self.main_window.output)
        self.main_window.output_layout.addWidget(QLabel("<b>Raw Console</b>"))
        self.main_window.output_layout.addWidget(self.main_window.raw_console_output)
        self.main_window.output_layout.addWidget(self.main_window.clear_output_btn)

        self.main_window.main_splitter.addWidget(self.main_window.output_panel)
        self.main_window.main_splitter.setSizes([700, 500])

    def create_modular_tabs(self) -> None:
        """Create all modular tab instances."""
        shared_context = {
            "main_window": self.main_window,
            "log_message": self.main_window.log_message,
            "app_context": self.main_window.app_context,
            "task_manager": self.main_window.task_manager,
        }

        self.main_window.dashboard_tab = DashboardTab(shared_context, self.main_window)
        self.main_window.analysis_tab = AnalysisTab(shared_context, self.main_window)
        self.main_window.exploitation_tab = ExploitationTab(shared_context, self.main_window)
        self.main_window.ai_assistant_tab = AIAssistantTab(shared_context, self.main_window)
        self.main_window.tools_tab = ToolsTab(shared_context, self.main_window)
        self.main_window.terminal_tab = TerminalTab(shared_context, self.main_window)
        self.main_window.settings_tab = SettingsTab(shared_context, self.main_window)
        self.main_window.workspace_tab = WorkspaceTab(shared_context, self.main_window)

        self.main_window.tabs.addTab(self.main_window.dashboard_tab, "Dashboard")
        self.main_window.tabs.addTab(self.main_window.workspace_tab, "Workspace")
        self.main_window.tabs.addTab(self.main_window.analysis_tab, "Analysis")
        self.main_window.tabs.addTab(self.main_window.exploitation_tab, "Exploitation")
        self.main_window.tabs.addTab(self.main_window.ai_assistant_tab, "AI Assistant")
        self.main_window.tabs.addTab(self.main_window.tools_tab, "Tools")
        self.main_window.tabs.addTab(self.main_window.terminal_tab, "Terminal")
        self.main_window.tabs.addTab(self.main_window.settings_tab, "Settings")
