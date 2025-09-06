"""Base class for plugin-based dialogs.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os

from intellicrack.handlers.pyqt6_handler import (
    QDateTime,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class PluginDialogBase(QDialog):
    """Base class for dialogs that work with plugins."""

    def __init__(self, parent=None, plugin_path: str = None):
        """Initialize the PluginDialogBase with default values."""
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.plugin_label = None
        self.init_dialog()

    def init_dialog(self):
        """Initialize dialog with default layout. Can be overridden by subclasses."""
        # Provide default implementation for base functionality
        self.setWindowTitle("Plugin Dialog")
        self.setMinimumSize(600, 400)

        # Create default layout
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Add plugin selection UI
        plugin_layout = self.create_plugin_selection_layout()
        layout.addLayout(plugin_layout)

        # Add main content area (can be customized by subclasses)
        self.content_area = QWidget()
        self.content_layout = QVBoxLayout(self.content_area)
        layout.addWidget(self.content_area)

        # Add standard dialog buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        button_layout.addWidget(self.ok_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

        # Load plugin if path was provided
        if self.plugin_path:
            self.load_plugin(self.plugin_path)

    def create_plugin_selection_layout(self):
        """Create the common plugin selection layout."""
        plugin_layout = QHBoxLayout()
        plugin_layout.addWidget(QLabel("Plugin:"))

        self.plugin_label = QLabel("No plugin selected")
        self.plugin_label.setStyleSheet("font-weight: bold;")
        plugin_layout.addWidget(self.plugin_label)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_plugin)
        plugin_layout.addWidget(browse_btn)

        plugin_layout.addStretch()
        return plugin_layout

    def browse_plugin(self):
        """Browse for a plugin file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin",
            "",
            "Python Files (*.py);;All Files (*.*)",
        )

        if file_path:
            self.load_plugin(file_path)

    def load_plugin(self, plugin_path: str):
        """Load a plugin file - to be overridden by subclasses."""
        if not os.path.exists(plugin_path):
            QMessageBox.warning(self, "Error", f"Plugin file not found: {plugin_path}")
            return False

        self.plugin_path = plugin_path
        self.plugin_label.setText(os.path.basename(plugin_path))

        # Subclasses should override this to add specific loading logic
        self.on_plugin_loaded(plugin_path)
        return True

    def on_plugin_loaded(self, plugin_path: str):
        """Called when a plugin is loaded - to be overridden by subclasses."""
        self.logger.debug(f"Plugin loaded from: {plugin_path}")

        # Store plugin metadata
        plugin_name = os.path.basename(plugin_path)
        plugin_dir = os.path.dirname(plugin_path)

        # Initialize plugin state tracking
        if not hasattr(self, "_loaded_plugins"):
            self._loaded_plugins = {}

        # Store plugin information
        self._loaded_plugins[plugin_path] = {
            "name": plugin_name,
            "directory": plugin_dir,
            "loaded_at": QDateTime.currentDateTime(),
            "status": "loaded",
        }

        # Update window title to reflect loaded plugin
        current_title = self.windowTitle()
        if " - " not in current_title:
            self.setWindowTitle(f"{current_title} - {plugin_name}")
        else:
            # Replace existing plugin name in title
            base_title = current_title.split(" - ")[0]
            self.setWindowTitle(f"{base_title} - {plugin_name}")

        # Enable any plugin-dependent UI elements
        if hasattr(self, "plugin_dependent_widgets"):
            for widget in self.plugin_dependent_widgets:
                widget.setEnabled(True)

        # Emit custom signal if available
        if hasattr(self, "plugin_loaded_signal"):
            self.plugin_loaded_signal.emit(plugin_path)

        # Log successful plugin loading
        self.logger.info(f"Successfully loaded plugin: {plugin_name}")

        # Store last loaded plugin for quick access
        self._last_loaded_plugin = plugin_path
