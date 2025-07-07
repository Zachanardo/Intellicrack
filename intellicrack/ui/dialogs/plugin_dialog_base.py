"""
Base class for plugin-based dialogs.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os

from PyQt6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
)


class PluginDialogBase(QDialog):
    """Base class for dialogs that work with plugins"""

    def __init__(self, parent=None, plugin_path: str = None):
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.plugin_label = None
        self.init_dialog()

    def init_dialog(self):
        """Initialize dialog - to be overridden by subclasses"""
        raise NotImplementedError("Subclasses must implement init_dialog()")

    def create_plugin_selection_layout(self):
        """Create the common plugin selection layout"""
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
        """Browse for a plugin file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Plugin", "", "Python Files (*.py);;All Files (*.*)"
        )

        if file_path:
            self.load_plugin(file_path)

    def load_plugin(self, plugin_path: str):
        """Load a plugin file - to be overridden by subclasses"""
        if not os.path.exists(plugin_path):
            QMessageBox.warning(self, "Error", f"Plugin file not found: {plugin_path}")
            return False

        self.plugin_path = plugin_path
        self.plugin_label.setText(os.path.basename(plugin_path))

        # Subclasses should override this to add specific loading logic
        self.on_plugin_loaded(plugin_path)
        return True

    def on_plugin_loaded(self, plugin_path: str):
        """Called when a plugin is loaded - to be overridden by subclasses"""
        self.logger.debug(f"Plugin loaded from: {plugin_path}")
        pass
