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
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

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

from ..utils.logger import log_all_methods
from .theme_manager import get_theme_manager


if TYPE_CHECKING:
    from .tabs.ai_assistant_tab import AIAssistantTab  # noqa: TC004
    from .tabs.analysis_tab import AnalysisTab  # noqa: TC004
    from .tabs.dashboard_tab import DashboardTab  # noqa: TC004
    from .tabs.exploitation_tab import ExploitationTab  # noqa: TC004
    from .tabs.settings_tab import SettingsTab  # noqa: TC004
    from .tabs.terminal_tab import TerminalTab  # noqa: TC004
    from .tabs.tools_tab import ToolsTab  # noqa: TC004
    from .tabs.workspace_tab import WorkspaceTab  # noqa: TC004


logger = logging.getLogger(__name__)


@runtime_checkable
class _MainWindowProtocol(Protocol):
    """Protocol defining the main window interface expected by UIManager.

    This protocol is runtime checkable, allowing isinstance() validation
    to verify that main window instances implement required methods.
    """

    central_widget: QWidget
    main_layout: QVBoxLayout
    main_splitter: QSplitter
    tabs: QTabWidget
    output_panel: QWidget
    output_layout: QVBoxLayout
    output: QTextEdit
    raw_console_output: QPlainTextEdit
    clear_output_btn: QPushButton
    dashboard_tab: DashboardTab
    analysis_tab: AnalysisTab
    exploitation_tab: ExploitationTab
    ai_assistant_tab: AIAssistantTab
    tools_tab: ToolsTab
    terminal_tab: TerminalTab
    settings_tab: SettingsTab
    workspace_tab: WorkspaceTab
    app_context: Any
    task_manager: Any

    def setCentralWidget(self, widget: QWidget) -> None: ...  # noqa: N802
    def create_toolbar(self) -> None: ...
    def clear_output(self) -> None: ...
    def log_message(self, message: str, level: str = "INFO") -> None: ...


@log_all_methods
class UIManager:
    """Manages the creation and layout of the main UI components."""

    def __init__(self, main_window: _MainWindowProtocol) -> None:
        """Initialize the UI Manager.

        Args:
            main_window: The main application window implementing _MainWindowProtocol.

        Raises:
            TypeError: If main_window does not implement required protocol methods.
        """
        required_methods = ["setCentralWidget", "create_toolbar", "clear_output", "log_message"]
        missing_methods = [
            method for method in required_methods
            if not callable(getattr(main_window, method, None))
        ]

        if missing_methods:
            missing_str = ", ".join(missing_methods)
            raise TypeError(
                f"main_window must implement _MainWindowProtocol. "
                f"Missing required methods: {missing_str}"
            )

        self.logger = logger
        self.main_window: _MainWindowProtocol = main_window
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
        from .tabs.ai_assistant_tab import AIAssistantTab
        from .tabs.analysis_tab import AnalysisTab
        from .tabs.dashboard_tab import DashboardTab
        from .tabs.exploitation_tab import ExploitationTab
        from .tabs.settings_tab import SettingsTab
        from .tabs.terminal_tab import TerminalTab
        from .tabs.tools_tab import ToolsTab
        from .tabs.workspace_tab import WorkspaceTab

        shared_context = {
            "main_window": self.main_window,
            "log_message": self.main_window.log_message,
            "app_context": self.main_window.app_context,
            "task_manager": self.main_window.task_manager,
        }

        parent_widget = cast("QWidget", self.main_window)
        self.main_window.dashboard_tab = DashboardTab(shared_context, parent_widget)
        self.main_window.analysis_tab = AnalysisTab(shared_context, parent_widget)
        self.main_window.exploitation_tab = ExploitationTab(shared_context, parent_widget)
        self.main_window.ai_assistant_tab = AIAssistantTab(shared_context, parent_widget)
        self.main_window.tools_tab = ToolsTab(shared_context, parent_widget)
        self.main_window.terminal_tab = TerminalTab(shared_context, parent_widget)
        self.main_window.settings_tab = SettingsTab(shared_context, parent_widget)
        self.main_window.workspace_tab = WorkspaceTab(shared_context, parent_widget)

        self.main_window.tabs.addTab(self.main_window.dashboard_tab, "Dashboard")
        self.main_window.tabs.addTab(self.main_window.workspace_tab, "Workspace")
        self.main_window.tabs.addTab(self.main_window.analysis_tab, "Analysis")
        self.main_window.tabs.addTab(self.main_window.exploitation_tab, "Exploitation")
        self.main_window.tabs.addTab(self.main_window.ai_assistant_tab, "AI Assistant")
        self.main_window.tabs.addTab(self.main_window.tools_tab, "Tools")
        self.main_window.tabs.addTab(self.main_window.terminal_tab, "Terminal")
        self.main_window.tabs.addTab(self.main_window.settings_tab, "Settings")
