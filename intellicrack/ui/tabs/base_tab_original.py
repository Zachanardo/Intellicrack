"""Original base tab class for Intellicrack.

This module provides the original base tab implementation,
maintained for compatibility purposes.

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

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from intellicrack.handlers.pyqt6_handler import QFont, Qt

"""UI module for Base Tab Original.

This module provides UI components and dialogs for base tab original functionality.
"""


class BaseTab(QWidget):
    """Base class for all main application tabs.
    Provides common functionality including loading states, shared context, and consistent styling.
    """

    def __init__(self, shared_context=None, parent=None):
        """Initialize the basetab.

        Args:
        shared_context: Initialization parameter
        parent: Initialization parameter

        """
        super().__init__(parent)
        self.shared_context = shared_context or {}
        self.is_loaded = False
        self.setup_loading_ui()

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
        print(f"[BaseTab] lazy_load_content called for {self.__class__.__name__}")
        print(f"[BaseTab] is_loaded before: {self.is_loaded}")
        if not self.is_loaded:
            print("[BaseTab] Clearing layout and calling setup_content...")
            self.clear_layout()
            self.setup_content()
            self.is_loaded = True
            print(f"[BaseTab] Content setup complete, is_loaded: {self.is_loaded}")
        else:
            print("[BaseTab] Content already loaded, skipping...")

    def setup_content(self):
        """Override this method to setup the actual tab content"""

    def clear_layout(self):
        """Clear all widgets and delete the existing layout"""
        print("[BaseTab] clear_layout() called")
        layout = self.layout()
        if layout:
            print("[BaseTab] Layout exists, clearing widgets...")
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
            # Delete the layout itself to prevent conflicts
            print("[BaseTab] Deleting layout...")
            layout.deleteLater()
            self.setLayout(None)
        print("[BaseTab] clear_layout() complete")

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
