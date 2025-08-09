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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class BaseTab(QWidget):
    """Base class for all main application tabs.
    Provides common functionality including loading states, shared context, and consistent styling.
    """

    def __init__(self, shared_context=None, parent=None):
        """Initialize base tab with shared application context and parent widget."""
        super().__init__(parent)

    def setup_loading_ui(self):
        """Setup initial loading state UI"""
        layout = QVBoxLayout(self)

        loading_label = QLabel("Loading...")
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        loading_label.setFont(font)

        layout.addWidget(loading_label)

    def lazy_load_content(self):
        """Override this method in subclasses to implement lazy loading.
        This method should create and setup the actual tab content.
        """
        if not self.is_loaded:
            self.clear_layout()
            self.setup_content()
            self.is_loaded = True

    def setup_content(self):
        """Override this method to setup the actual tab content"""

    def clear_layout(self):
        """Clear all widgets from the current layout"""
        layout = self.layout()
        if layout:
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

    def log_activity(self, message):
        """Log activity to shared context if available"""
        if self.shared_context and hasattr(self.shared_context, "log_activity"):
            self.shared_context.log_activity(message)

    @property
    def app_context(self):
        """Get the application context from shared context"""
        return self.shared_context.get("app_context")

    @property
    def task_manager(self):
        """Get the task manager from shared context"""
        return self.shared_context.get("task_manager")

    @property
    def main_window(self):
        """Get the main window from shared context"""
        return self.shared_context.get("main_window")

    def submit_task(self, task):
        """Submit a task to the task manager"""
        if self.task_manager:
            return self.task_manager.submit_task(task)
        return None

    def submit_callable(self, func, args=(), kwargs=None, description=""):
        """Submit a callable to the task manager"""
        if self.task_manager:
            return self.task_manager.submit_callable(func, args, kwargs, description=description)
        return None
