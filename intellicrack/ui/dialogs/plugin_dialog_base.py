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

import logging
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

    def __init__(self, parent: QWidget | None = None, plugin_path: str | None = None) -> None:
        """Initialize the PluginDialogBase with default values.

        Args:
            parent: The parent widget. Defaults to None.
            plugin_path: Path to the plugin file. Defaults to None.

        """
        super().__init__(parent)
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
        self.plugin_path: str | None = plugin_path
        self.plugin_label: QLabel | None = None
        self.content_area: QWidget | None = None
        self.content_layout: QVBoxLayout | None = None
        self.ok_button: QPushButton | None = None
        self.cancel_button: QPushButton | None = None
        self._loaded_plugins: dict[str, dict[str, str | object]] = {}
        self._last_loaded_plugin: str | None = None
        self.init_dialog()

    def init_dialog(self) -> None:
        """Initialize the dialog with default layout and widgets.

        Can be overridden by subclasses to customize the dialog appearance.
        """
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

    def create_plugin_selection_layout(self) -> QHBoxLayout:
        """Create the common plugin selection layout.

        Returns:
            A horizontal layout containing the plugin selection UI.

        """
        plugin_layout = QHBoxLayout()
        plugin_layout.addWidget(QLabel("Plugin:"))

        self.plugin_label = QLabel("No plugin selected")
        if self.plugin_label is not None:
            self.plugin_label.setStyleSheet("font-weight: bold;")
        plugin_layout.addWidget(self.plugin_label)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_plugin)
        plugin_layout.addWidget(browse_btn)

        plugin_layout.addStretch()
        return plugin_layout

    def browse_plugin(self) -> None:
        """Open a file dialog to browse and select a plugin file.

        Updates the plugin path and loads the selected plugin if a valid
        file is chosen.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin",
            "",
            "Python Files (*.py);;All Files (*.*)",
        )

        if file_path:
            self.load_plugin(file_path)

    def load_plugin(self, plugin_path: str) -> bool:
        """Load a plugin file.

        Validates the plugin file exists, updates the plugin path, and calls
        on_plugin_loaded for subclass-specific handling. Can be overridden by
        subclasses to customize loading logic.

        Args:
            plugin_path: Path to the plugin file to load.

        Returns:
            bool: True if the plugin was loaded successfully, False otherwise.
        """
        if not os.path.exists(plugin_path):
            QMessageBox.warning(self, "Error", f"Plugin file not found: {plugin_path}")
            return False

        self.plugin_path = plugin_path
        if self.plugin_label is not None:
            self.plugin_label.setText(os.path.basename(plugin_path))

        # Subclasses should override this to add specific loading logic
        self.on_plugin_loaded(plugin_path)
        return True

    def on_plugin_loaded(self, plugin_path: str) -> None:
        """Handle plugin loading completion.

        Updates the plugin information cache, window title, enables plugin-
        dependent widgets, and emits plugin loaded signal. Can be overridden by
        subclasses to add custom handling.

        Args:
            plugin_path: Path to the plugin file that was loaded.
        """
        self.logger.debug("Plugin loaded from: %s", plugin_path)

        plugin_name: str = os.path.basename(plugin_path)
        plugin_dir: str = os.path.dirname(plugin_path)

        self._loaded_plugins[plugin_path] = {
            "name": plugin_name,
            "directory": plugin_dir,
            "loaded_at": QDateTime.currentDateTime(),
            "status": "loaded",
        }

        current_title: str = self.windowTitle()
        if " - " not in current_title:
            self.setWindowTitle(f"{current_title} - {plugin_name}")
        else:
            base_title: str = current_title.split(" - ", maxsplit=1)[0]
            self.setWindowTitle(f"{base_title} - {plugin_name}")

        if hasattr(self, "plugin_dependent_widgets"):
            plugin_dependent_widgets = self.plugin_dependent_widgets
            if plugin_dependent_widgets is not None:
                for widget in plugin_dependent_widgets:
                    widget.setEnabled(True)

        if hasattr(self, "plugin_loaded_signal"):
            plugin_loaded_signal = self.plugin_loaded_signal
            if plugin_loaded_signal is not None:
                plugin_loaded_signal.emit(plugin_path)

        self.logger.info("Successfully loaded plugin: %s", plugin_name)
        self._last_loaded_plugin = plugin_path
