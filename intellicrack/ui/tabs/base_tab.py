"""Base tab class for Intellicrack.

This module provides the base tab class that other tabs inherit from,
providing common functionality and interface structure.

Copyright (C) 2025 Zachary Flint

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
"""

from collections.abc import Callable
from typing import Any

from intellicrack.handlers.pyqt6_handler import QFont, QLabel, Qt, QVBoxLayout, QWidget


class BaseTab(QWidget):
    """Base class for all main application tabs.

    Provides common functionality including loading states, shared context, and consistent styling.
    """

    def __init__(self, shared_context: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
        """Initialize base tab with shared application context and parent widget.

        Args:
            shared_context: Shared application context dictionary containing app_context, task_manager, and main_window.
            parent: Parent QWidget for this tab.

        """
        super().__init__(parent)
        self.shared_context: dict[str, Any] = shared_context or {}
        self.is_loaded: bool = False

        # Setup initial loading UI
        self.setup_loading_ui()

        # Auto-load content immediately
        self.lazy_load_content()

    def setup_loading_ui(self) -> None:
        """Set up initial loading state UI.

        Creates a centered loading label displayed while tab content is being initialized.
        """
        layout = QVBoxLayout(self)

        loading_label = QLabel("Loading...")
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        loading_label.setFont(font)

        layout.addWidget(loading_label)

    def lazy_load_content(self) -> None:
        """Override this method in subclasses to implement lazy loading.

        This method should create and setup the actual tab content. Called automatically
        during initialization to load tab content after the loading UI is displayed.

        Notes:
            Sets is_loaded flag to True after successful content setup to prevent
            redundant initialization.

        """
        if not self.is_loaded:
            self.clear_layout()
            self.setup_content()
            self.is_loaded = True

    def setup_content(self) -> None:
        """Override this method to setup the actual tab content.

        Subclasses should implement this method to create and configure their
        specific UI components and layouts.
        """

    def clear_layout(self) -> None:
        """Clear all widgets from the current layout.

        Removes and schedules deletion of all child widgets in the current layout.
        Used to reset the tab UI before loading new content.
        """
        if layout := self.layout():
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

    def log_activity(self, message: str) -> None:
        """Log activity to shared context if available.

        Args:
            message: Activity message to log to the shared context logger.

        """
        if self.shared_context and hasattr(self.shared_context, "log_activity"):
            self.shared_context.log_activity(message)

    @property
    def app_context(self) -> object:
        """Get the application context from shared context.

        Returns:
            Application context object if available, None otherwise.

        """
        return self.shared_context.get("app_context")

    @property
    def task_manager(self) -> object:
        """Get the task manager from shared context.

        Returns:
            Task manager instance for submitting background tasks, None if not available.

        """
        return self.shared_context.get("task_manager")

    @property
    def main_window(self) -> object:
        """Get the main window from shared context.

        Returns:
            Main application window instance, None if not available.

        """
        return self.shared_context.get("main_window")

    def submit_task(self, task: object) -> object:
        """Submit a task to the task manager.

        Args:
            task: Task object to submit for background execution.

        Returns:
            Task result or future if task manager is available, None otherwise.

        """
        return self.task_manager.submit_task(task) if self.task_manager else None

    def submit_callable(
        self,
        func: Callable[..., object],
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        description: str = "",
    ) -> object:
        """Submit a callable to the task manager.

        Args:
            func: Callable function to execute in background task.
            args: Positional arguments to pass to the callable.
            kwargs: Keyword arguments to pass to the callable.
            description: Human-readable description of the task.

        Returns:
            Task result or future if task manager is available, None otherwise.

        """
        if self.task_manager:
            return self.task_manager.submit_callable(func, args, kwargs, description=description)
        return None
