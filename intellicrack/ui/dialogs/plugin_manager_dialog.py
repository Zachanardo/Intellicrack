"""Plugin Manager Dialog for Intellicrack.

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
import shutil
import zipfile

# Optional imports with graceful fallbacks
from .common_imports import (
    HAS_PYQT,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    logger,
    pyqtSignal,
)

# Additional imports specific to plugin manager
if not HAS_PYQT:

    class PluginInstallThread:
        """Stub class for plugin installation thread when PyQt6 is not available.

        Provides a placeholder to prevent import errors in non-GUI environments.
        """

    class PluginManagerDialog:
        """Stub class for plugin manager dialog when PyQt6 is not available.

        Provides minimal interface methods to allow code to run without PyQt6.
        """

        def __init__(self, parent=None):
            """Initialize stub plugin manager dialog for non-GUI environments."""
            self.parent = parent

            # Initialize UI attributes
            self.author_edit = None
            self.auto_enable = None
            self.available_list = None
            self.backup_existing = None
            self.configure_btn = None
            self.disable_btn = None
            self.enable_btn = None
            self.file_path_edit = None
            self.install_btn = None
            self.install_thread = None
            self.installed_list = None
            self.plugin_details = None
            self.plugin_info = None
            self.plugin_name_edit = None
            self.plugin_type_combo = None
            self.preview_btn = None
            self.progress_bar = None
            self.remove_btn = None
            self.repo_combo = None
            self.status_label = None
            self.test_file_edit = None
            self.test_output = None

        def show(self):
            """Show the dialog (no-op when PyQt6 is not available)."""

        def exec_(self):
            """Execute the dialog modally (no-op when PyQt6 is not available).

            Returns:
                int: Always returns 0

            """
            return 0

        def exec(self):
            """Execute the dialog modally - PyQt6 style method (no-op when PyQt6 is not available).

            Returns:
                int: Always returns 0

            """
            return 0
else:

    class PluginInstallThread(QThread):
        """Thread for installing plugins without blocking the UI."""

        progress_updated = pyqtSignal(int)
        status_updated = pyqtSignal(str)
        installation_finished = pyqtSignal(bool, str)

        def __init__(self, plugin_path: str, install_dir: str):
            """Initialize plugin installation thread with source path and destination directory."""
            super().__init__()
            self.plugin_path = plugin_path
            self.install_dir = install_dir

        def run(self):
            """Install plugin in background thread."""
            try:
                self.status_updated.emit("Extracting plugin...")
                self.progress_updated.emit(25)

                # Extract plugin if it's a zip file
                if self.plugin_path.endswith(".zip"):
                    with zipfile.ZipFile(self.plugin_path, "r") as zip_ref:
                        zip_ref.extractall(self.install_dir)
                else:
                    # Copy single file
                    shutil.copy2(self.plugin_path, self.install_dir)

                self.progress_updated.emit(75)
                self.status_updated.emit("Validating plugin...")

                # Basic validation
                plugin_files = os.listdir(self.install_dir)
                if any(_f.endswith(".py") for _f in plugin_files):
                    self.progress_updated.emit(100)
                    self.status_updated.emit("Installation complete")
                    self.installation_finished.emit(True, "Plugin installed successfully")
                else:
                    self.installation_finished.emit(False, "No Python files found in plugin")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in plugin_manager_dialog: %s", e)
                self.installation_finished.emit(False, f"Installation failed: {e!s}")

    class PluginManagerDialog(QDialog):
        """Dialog for managing Intellicrack plugins."""

        def __init__(self, parent=None, app_context=None):
            """Initialize plugin manager dialog with plugin discovery and management capabilities."""
            super().__init__(parent)
            self.setWindowTitle("Plugin Manager")
            self.setMinimumSize(900, 600)

            # App context
            self.app_context = app_context

            # Plugin management
            self.installed_plugins = {}
            self.available_plugins = {}
            self.plugin_categories = ["Analysis", "Exploitation", "Network", "UI", "Utilities"]

            # Threading
            self.install_thread = None
            self.discovery_thread = None

            # Current state
            self.current_plugin = None
            self.filter_category = "All"
            self.search_text = ""

            # Setup UI
            self.setup_ui()
            self.setup_connections()

            # Load plugins
            self.refresh_plugin_lists()

            # Setup drag and drop
            self.setAcceptDrops(True)

            # Load settings
            self.load_settings()

            # Auto-refresh timer
            self.auto_refresh_timer = QTimer()
            self.auto_refresh_timer.timeout.connect(self.auto_refresh_plugins)

            # Check for updates on startup
            if hasattr(self.app_context, "config") and self.app_context.config.get(
                "plugin_auto_update", True
            ):
                QTimer.singleShot(2000, self.check_for_updates)

            logger.info("Plugin Manager Dialog initialized")

            # Show welcome message for first time users
            if not hasattr(self.app_context, "plugin_manager_shown_before"):
                self.show_welcome_message()
                if hasattr(self.app_context, "config"):
                    self.app_context.config["plugin_manager_shown_before"] = True

        def setup_ui(self):
            """Set up the user interface."""
            self.setWindowTitle("Plugin Manager")
            self.setModal(True)
            self.resize(800, 600)

            layout = QVBoxLayout(self)

            # Create tab widget
            tab_widget = QTabWidget()

            # Installed plugins tab
            installed_tab = QWidget()
            self.setup_installed_tab(installed_tab)
            tab_widget.addTab(installed_tab, "Installed Plugins")

            # Available plugins tab
            available_tab = QWidget()
            self.setup_available_tab(available_tab)
            tab_widget.addTab(available_tab, "Available Plugins")

            # Install from file tab
            install_tab = QWidget()
            self.setup_install_tab(install_tab)
            tab_widget.addTab(install_tab, "Install from File")

            # Plugin development tab
            dev_tab = QWidget()
            self.setup_development_tab(dev_tab)
            tab_widget.addTab(dev_tab, "Plugin Development")

            layout.addWidget(tab_widget)

            # Dialog buttons
            button_layout = QHBoxLayout()

            refresh_btn = QPushButton("Refresh")
            refresh_btn.clicked.connect(self.refresh_plugins)

            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)

            button_layout.addWidget(refresh_btn)
            button_layout.addStretch()
            button_layout.addWidget(close_btn)

            layout.addLayout(button_layout)

        def setup_installed_tab(self, tab):
            """Setup the installed plugins tab."""
            layout = QVBoxLayout(tab)

            # Header
            header_group = QGroupBox("Installed Plugins")
            header_layout = QVBoxLayout(header_group)

            self.installed_list = QListWidget()
            header_layout.addWidget(self.installed_list)

            # Plugin controls
            controls_layout = QHBoxLayout()

            self.enable_btn = QPushButton("Enable")
            self.enable_btn.clicked.connect(self.enable_selected_plugin)

            self.disable_btn = QPushButton("Disable")
            self.disable_btn.clicked.connect(self.disable_selected_plugin)

            self.remove_btn = QPushButton("Remove")
            self.remove_btn.clicked.connect(self.remove_selected_plugin)

            self.configure_btn = QPushButton("Configure")
            self.configure_btn.clicked.connect(self.configure_selected_plugin)

            controls_layout.addWidget(self.enable_btn)
            controls_layout.addWidget(self.disable_btn)
            controls_layout.addWidget(self.remove_btn)
            controls_layout.addWidget(self.configure_btn)
            controls_layout.addStretch()

            header_layout.addLayout(controls_layout)

            # Plugin info
            info_group = QGroupBox("Plugin Information")
            info_layout = QVBoxLayout(info_group)

            self.plugin_info = QTextEdit()
            self.plugin_info.setReadOnly(True)
            self.plugin_info.setMaximumHeight(150)
            info_layout.addWidget(self.plugin_info)

            layout.addWidget(header_group)
            layout.addWidget(info_group)

            # Connect selection change
            self.installed_list.itemSelectionChanged.connect(self.on_installed_selection_changed)

        def setup_available_tab(self, tab):
            """Setup the available plugins tab."""
            layout = QVBoxLayout(tab)

            # Repository selection
            repo_group = QGroupBox("Plugin Repository")
            repo_layout = QHBoxLayout(repo_group)

            repo_layout.addWidget(QLabel("Repository:"))
            self.repo_combo = QComboBox()
            self.repo_combo.addItems(
                ["Official Repository", "Community Repository", "Local Repository"]
            )
            repo_layout.addWidget(self.repo_combo)

            refresh_repo_btn = QPushButton("Refresh")
            refresh_repo_btn.clicked.connect(self.refresh_available_plugins)
            repo_layout.addWidget(refresh_repo_btn)

            layout.addWidget(repo_group)

            # Available plugins list
            available_group = QGroupBox("Available Plugins")
            available_layout = QVBoxLayout(available_group)

            self.available_list = QListWidget()
            available_layout.addWidget(self.available_list)

            # Install controls
            install_layout = QHBoxLayout()

            self.install_btn = QPushButton("Install Selected")
            self.install_btn.clicked.connect(self.install_selected_plugin)

            self.preview_btn = QPushButton("Preview")
            self.preview_btn.clicked.connect(self.preview_selected_plugin)

            install_layout.addWidget(self.install_btn)
            install_layout.addWidget(self.preview_btn)
            install_layout.addStretch()

            available_layout.addLayout(install_layout)

            layout.addWidget(available_group)

            # Plugin details
            details_group = QGroupBox("Plugin Details")
            details_layout = QVBoxLayout(details_group)

            self.plugin_details = QTextEdit()
            self.plugin_details.setReadOnly(True)
            self.plugin_details.setMaximumHeight(150)
            details_layout.addWidget(self.plugin_details)

            layout.addWidget(details_group)

            # Connect selection change
            self.available_list.itemSelectionChanged.connect(self.on_available_selection_changed)

        def setup_install_tab(self, tab):
            """Setup the install from file tab."""
            layout = QVBoxLayout(tab)

            # File selection
            file_group = QGroupBox("Install Plugin from File")
            file_layout = QFormLayout(file_group)

            self.file_path_edit = QLineEdit()
            browse_btn = QPushButton("Browse...")
            browse_btn.clicked.connect(self.browse_plugin_file)

            file_selection_layout = QHBoxLayout()
            file_selection_layout.addWidget(self.file_path_edit)
            file_selection_layout.addWidget(browse_btn)

            file_layout.addRow("Plugin File:", file_selection_layout)

            # Installation options
            self.auto_enable = QCheckBox("Auto-enable after installation")
            self.auto_enable.setChecked(True)

            self.backup_existing = QCheckBox("Backup existing plugins")
            self.backup_existing.setChecked(True)

            file_layout.addRow(self.auto_enable)
            file_layout.addRow(self.backup_existing)

            layout.addWidget(file_group)

            # Installation progress
            progress_group = QGroupBox("Installation Progress")
            progress_layout = QVBoxLayout(progress_group)

            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            progress_layout.addWidget(self.progress_bar)

            self.status_label = QLabel("Ready to install plugin")
            progress_layout.addWidget(self.status_label)

            layout.addWidget(progress_group)

            # Install button
            install_file_btn = QPushButton("Install Plugin")
            install_file_btn.clicked.connect(self.install_from_file)
            layout.addWidget(install_file_btn)

            layout.addStretch()

        def setup_development_tab(self, tab):
            """Setup the plugin development tab."""
            layout = QVBoxLayout(tab)

            # Template selection
            template_group = QGroupBox("Create New Plugin")
            template_layout = QFormLayout(template_group)

            self.plugin_name_edit = QLineEdit()
            template_layout.addRow("Plugin Name:", self.plugin_name_edit)

            self.plugin_type_combo = QComboBox()
            self.plugin_type_combo.addItems(
                [
                    "Analysis Plugin",
                    "Exploit Plugin",
                    "UI Plugin",
                    "Tool Plugin",
                    "Generic Plugin",
                ]
            )
            template_layout.addRow("Plugin Type:", self.plugin_type_combo)

            self.author_edit = QLineEdit()
            template_layout.addRow("Author:", self.author_edit)

            create_btn = QPushButton("Create Plugin Template")
            create_btn.clicked.connect(self.create_plugin_template)
            template_layout.addRow(create_btn)

            layout.addWidget(template_group)

            # Plugin testing
            test_group = QGroupBox("Plugin Testing")
            test_layout = QVBoxLayout(test_group)

            test_info = QLabel("Select a plugin file to test:")
            test_layout.addWidget(test_info)

            test_file_layout = QHBoxLayout()
            self.test_file_edit = QLineEdit()
            test_browse_btn = QPushButton("Browse...")
            test_browse_btn.clicked.connect(self.browse_test_plugin)

            test_file_layout.addWidget(self.test_file_edit)
            test_file_layout.addWidget(test_browse_btn)
            test_layout.addLayout(test_file_layout)

            test_btn = QPushButton("Test Plugin")
            test_btn.clicked.connect(self.test_plugin)
            test_layout.addWidget(test_btn)

            self.test_output = QTextEdit()
            self.test_output.setReadOnly(True)
            self.test_output.setMaximumHeight(200)
            test_layout.addWidget(self.test_output)

            layout.addWidget(test_group)

            layout.addStretch()

        def load_installed_plugins(self):
            """Load list of installed plugins."""
            self.installed_plugins = []
            self.installed_list.clear()

            try:
                if os.path.exists(self.plugins_dir):
                    for item in os.listdir(self.plugins_dir):
                        item_path = os.path.join(self.plugins_dir, item)
                        if os.path.isdir(item_path) or item.endswith(".py"):
                            plugin_info = self.get_plugin_info(item_path)
                            self.installed_plugins.append(plugin_info)

                            list_item = QListWidgetItem(plugin_info["name"])
                            list_item.setData(0, plugin_info)

                            # Color code based on status
                            if plugin_info.get("enabled", True):
                                list_item.setForeground(list_item.foreground())  # Default color
                            else:
                                from PyQt6.QtGui import QColor

                                list_item.setForeground(QColor(128, 128, 128))  # Gray for disabled

                            self.installed_list.addItem(list_item)
            except Exception as e:
                logger.error(f"Error loading installed plugins: {e}")

        def load_available_plugins(self):
            """Load list of available plugins from repositories."""
            self.available_plugins = []
            self.available_list.clear()

            # Simulate available plugins (in real implementation, would fetch from repositories)
            demo_plugins = [
                {
                    "name": "License Bypass Helper",
                    "version": "1.2.0",
                    "description": "Advanced license validation bypass techniques",
                    "author": "Community",
                    "category": "Analysis",
                    "size": "45 KB",
                },
                {
                    "name": "Packer Detector Pro",
                    "version": "2.1.0",
                    "description": "Detect and analyze various executable packers",
                    "author": "Security Team",
                    "category": "Analysis",
                    "size": "128 KB",
                },
                {
                    "name": "Frida Script Generator",
                    "version": "1.0.5",
                    "description": "Generate custom Frida scripts for dynamic analysis",
                    "author": "Dev Team",
                    "category": "Tool",
                    "size": "67 KB",
                },
            ]

            for plugin in demo_plugins:
                self.available_plugins.append(plugin)
                list_item = QListWidgetItem(f"{plugin['name']} v{plugin['version']}")
                list_item.setData(0, plugin)
                self.available_list.addItem(list_item)

        def get_plugin_info(self, plugin_path):
            """Extract information about a plugin."""
            info = {
                "name": os.path.basename(plugin_path),
                "path": plugin_path,
                "type": "file" if os.path.isfile(plugin_path) else "directory",
                "enabled": True,
                "version": "1.0.0",
                "description": "No description available",
            }

            # Try to read plugin metadata
            try:
                if plugin_path.endswith(".py"):
                    with open(plugin_path, encoding="utf-8") as f:
                        content = f.read()

                    # Extract basic metadata from comments
                    lines = content.split("\n")
                    for line in lines[:20]:  # Check first 20 lines
                        line = line.strip()
                        if line.startswith("# Name:"):
                            info["name"] = line.split(":", 1)[1].strip()
                        elif line.startswith("# Version:"):
                            info["version"] = line.split(":", 1)[1].strip()
                        elif line.startswith("# Description:"):
                            info["description"] = line.split(":", 1)[1].strip()
                        elif "def " in line and "main" in line:
                            info["has_main"] = True

            except Exception as e:
                logger.debug(f"Could not read plugin metadata: {e}")

            return info

        def on_installed_selection_changed(self):
            """Handle selection change in installed plugins list."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                info_text = f"""Plugin: {plugin_info['name']}
Version: {plugin_info.get('version', 'Unknown')}
Type: {plugin_info['type']}
Path: {plugin_info['path']}
Status: {'Enabled' if plugin_info.get('enabled', True) else 'Disabled'}

Description: {plugin_info.get('description', 'No description available')}"""
                self.plugin_info.setPlainText(info_text)
            else:
                self.plugin_info.clear()

        def on_available_selection_changed(self):
            """Handle selection change in available plugins list."""
            current_item = self.available_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                details_text = f"""Plugin: {plugin_info['name']}
Version: {plugin_info['version']}
Author: {plugin_info['author']}
Category: {plugin_info['category']}
Size: {plugin_info['size']}

Description: {plugin_info['description']}"""
                self.plugin_details.setPlainText(details_text)
            else:
                self.plugin_details.clear()

        def enable_selected_plugin(self):
            """Enable the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                plugin_info["enabled"] = True
                current_item.setData(0, plugin_info)
                current_item.setForeground(current_item.foreground())  # Reset to default color
                self.on_installed_selection_changed()  # Refresh info display
                QMessageBox.information(self, "Success", f"Plugin '{plugin_info['name']}' enabled")

        def disable_selected_plugin(self):
            """Disable the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                plugin_info["enabled"] = False
                current_item.setData(0, plugin_info)
                from PyQt6.QtGui import QColor

                current_item.setForeground(QColor(128, 128, 128))  # Gray out
                self.on_installed_selection_changed()  # Refresh info display
                QMessageBox.information(self, "Success", f"Plugin '{plugin_info['name']}' disabled")

        def remove_selected_plugin(self):
            """Remove the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                reply = QMessageBox.question(
                    self,
                    "Confirm Removal",
                    f"Are you sure you want to remove plugin '{plugin_info['name']}'?",
                    QMessageBox.Yes | QMessageBox.No,
                )

                if reply == QMessageBox.Yes:
                    try:
                        if os.path.isfile(plugin_info["path"]):
                            os.remove(plugin_info["path"])
                        elif os.path.isdir(plugin_info["path"]):
                            shutil.rmtree(plugin_info["path"])

                        self.load_installed_plugins()  # Refresh list
                        QMessageBox.information(self, "Success", "Plugin removed successfully")
                    except Exception as e:
                        logger.error("Exception in plugin_manager_dialog: %s", e)
                        QMessageBox.critical(self, "Error", f"Failed to remove plugin: {e!s}")

        def configure_selected_plugin(self):
            """Configure the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                QMessageBox.information(
                    self,
                    "Plugin Configuration",
                    f"Configuration for '{plugin_info['name']}' is not yet implemented.\n\n"
                    "This feature will allow you to modify plugin settings and parameters.",
                )

        def install_selected_plugin(self):
            """Install the selected available plugin."""
            current_item = self.available_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                QMessageBox.information(
                    self,
                    "Plugin Installation",
                    f"Installation of '{plugin_info['name']}' from repository is not yet implemented.\n\n"
                    "This feature will download and install plugins from online repositories.",
                )

        def preview_selected_plugin(self):
            """Preview the selected available plugin."""
            current_item = self.available_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                QMessageBox.information(
                    self,
                    "Plugin Preview",
                    f"Preview for '{plugin_info['name']}':\n\n"
                    f"Description: {plugin_info['description']}\n"
                    f"Version: {plugin_info['version']}\n"
                    f"Author: {plugin_info['author']}\n"
                    f"Category: {plugin_info['category']}\n\n"
                    "Full preview functionality coming soon.",
                )

        def browse_plugin_file(self):
            """Browse for a plugin file to install."""
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Plugin File",
                "",
                "Plugin Files (*.py *.zip);;Python Files (*.py);;ZIP Archives (*.zip);;All Files (*)",
            )

            if file_path:
                self.file_path_edit.setText(file_path)

        def install_from_file(self):
            """Install plugin from selected file."""
            plugin_file = self.file_path_edit.text().strip()
            if not plugin_file:
                QMessageBox.warning(self, "Warning", "Please select a plugin file first")
                return

            if not os.path.exists(plugin_file):
                QMessageBox.critical(self, "Error", "Selected file does not exist")
                return

            # Start installation thread
            install_dir = os.path.join(
                self.plugins_dir, os.path.splitext(os.path.basename(plugin_file))[0]
            )
            os.makedirs(install_dir, exist_ok=True)

            self.install_thread = PluginInstallThread(plugin_file, install_dir)
            self.install_thread.progress_updated.connect(self.progress_bar.setValue)
            self.install_thread.status_updated.connect(self.status_label.setText)
            self.install_thread.installation_finished.connect(self.on_installation_finished)

            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.install_thread.start()

        def on_installation_finished(self, success, message):
            """Handle installation completion."""
            self.progress_bar.setVisible(False)

            if success:
                QMessageBox.information(self, "Success", message)
                self.load_installed_plugins()  # Refresh installed plugins list

                if self.auto_enable.isChecked():
                    self.status_label.setText("Plugin installed and enabled")
                else:
                    self.status_label.setText("Plugin installed (disabled)")
            else:
                QMessageBox.critical(self, "Installation Failed", message)
                self.status_label.setText("Installation failed")

        def create_plugin_template(self):
            """Create a new plugin template."""
            plugin_name = self.plugin_name_edit.text().strip()
            if not plugin_name:
                QMessageBox.warning(self, "Warning", "Please enter a plugin name")
                return

            plugin_type = self.plugin_type_combo.currentText()
            author = self.author_edit.text().strip() or "Unknown Author"

            # Generate template code
            template_code = f"""#!/usr/bin/env python3
\"\"\"
{plugin_name} - {plugin_type} for Intellicrack

Author: {author}
Version: 1.0.0
Description: Auto-generated plugin template
\"\"\"

import logging
import os
import time
import hashlib
import traceback
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class {plugin_name.replace(' ', '')}Plugin:
    \"\"\"
    {plugin_name} plugin implementation.
    \"\"\"

    def __init__(self):
        \"\"\"Initialize the plugin.\"\"\"
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "Auto-generated {plugin_type.lower()}"
        self.author = "{author}"
        self.categories = ["{plugin_type.lower()}"]

        # Plugin state
        self.app = None
        self.cache = {{}}
        self.temp_files = []
        self.open_handles = []
        self.analysis_count = 0
        self.last_analysis = None

    def initialize(self, app_instance) -> bool:
        \"\"\"
        Initialize the plugin with the application instance.

        Args:
            app_instance: Main application instance

        Returns:
            bool: True if initialization successful
        \"\"\"
        try:
            self.app = app_instance
            logger.info(f"{{self.name}} plugin initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize {{self.name}} plugin: {{e}}")
            return False

    def validate_binary(self, binary_path: str) -> tuple[bool, str]:
        \"\"\"
        Validate binary file before analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            Tuple of (is_valid, error_message)
        \"\"\"
        if not binary_path:
            return False, "No binary path provided"

        if not os.path.exists(binary_path):
            return False, f"File does not exist: {{binary_path}}"

        if not os.path.isfile(binary_path):
            return False, f"Path is not a file: {{binary_path}}"

        if not os.access(binary_path, os.R_OK):
            return False, f"File is not readable: {{binary_path}}"

        # Check file size (100MB limit by default)
        max_size = 100 * 1024 * 1024
        try:
            file_size = os.path.getsize(binary_path)
            if file_size > max_size:
                return False, f"File too large: {{file_size}} bytes (max: {{max_size}})"
        except OSError as e:
            logger.error("OS error in plugin_manager_dialog: %s", e)
            return False, f"Could not get file size: {{str(e)}}"

        return True, "Valid"

    def _perform_analysis(self, binary_path: str, *args, **kwargs) -> Dict[str, Any]:
        \"\"\"
        Perform the actual analysis based on plugin type.

        Args:
            binary_path: Path to binary file
            *args: Additional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Analysis results dictionary
        \"\"\"
        start_time = time.time()

        # Check cache
        if binary_path and binary_path in self.cache:
            cached_result = self.cache[binary_path]
            cached_result['from_cache'] = True
            return cached_result

        results = {{
            'plugin_type': '{plugin_type.lower()}',
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': []
        }}

        try:
            if binary_path:
                # Basic file analysis
                file_info = self._analyze_file_info(binary_path)
                results['file_info'] = file_info

                # Plugin-type specific analysis
                if '{plugin_type.lower()}' == 'analysis':
                    results['analysis'] = self._perform_binary_analysis(binary_path)
                elif '{plugin_type.lower()}' == 'packer':
                    results['packer_detection'] = self._detect_packers(binary_path)
                elif '{plugin_type.lower()}' == 'network':
                    results['network_analysis'] = self._analyze_network_behavior(binary_path)
                elif '{plugin_type.lower()}' == 'vulnerability':
                    results['vulnerabilities'] = self._scan_vulnerabilities(binary_path)
                else:
                    # Generic analysis
                    with open(binary_path, 'rb') as f:
                        header = f.read(1024)
                    results['header_analysis'] = {{
                        'first_bytes': header[:16].hex(),
                        'contains_pe_header': b'MZ' in header[:2],
                        'contains_elf_header': header[:4] == b'\\x7fELF'
                    }}

                # Update cache
                if binary_path:
                    self.cache[binary_path] = results.copy()

            # Process any additional arguments
            if args:
                results['additional_args'] = list(args)
            if kwargs:
                results['additional_kwargs'] = dict(kwargs)

        except Exception as e:
            results['error'] = str(e)
            results['traceback'] = traceback.format_exc()
            logger.error(f"Analysis failed: {{e}}")

        # Calculate execution time
        execution_time = time.time() - start_time
        results['execution_time'] = execution_time

        # Update statistics
        self.analysis_count += 1
        self.last_analysis = time.time()

        return results

    def _analyze_file_info(self, file_path: str) -> Dict[str, Any]:
        \"\"\"Get basic file information.\"\"\"
        path = Path(file_path)
        stat = path.stat()

        # Calculate file hash
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)

        return {{
            'name': path.name,
            'size': stat.st_size,
            'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
            'sha256': sha256_hash.hexdigest()
        }}

    def _perform_binary_analysis(self, binary_path: str) -> Dict[str, Any]:
        \"\"\"Perform binary analysis.\"\"\"
        import os
        import hashlib

        findings = []

        try:
            if not os.path.exists(binary_path):
                return {{
                    'type': 'binary_analysis',
                    'status': 'error',
                    'findings': [f'File not found: {{binary_path}}']
                }}

            # Basic file analysis
            file_size = os.path.getsize(binary_path)
            findings.append(f'File size: {{file_size:,}} bytes')

            # File hash calculation
            with open(binary_path, 'rb') as f:
                file_data = f.read()
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            findings.append(f'MD5: {{md5_hash}}')
            findings.append(f'SHA256: {{sha256_hash}}')

            # File type detection
            if file_data.startswith(b'MZ'):
                findings.append('File type: Windows PE executable')
                # Basic PE analysis
                if b'This program cannot be run in DOS mode' in file_data:
                    findings.append('Valid PE header detected')
            elif file_data.startswith(b'\\x7fELF'):
                findings.append('File type: Linux ELF executable')
            elif file_data.startswith(b'\\xca\\xfe\\xba\\xbe'):
                findings.append('File type: macOS Mach-O executable')
            else:
                findings.append('File type: Unknown or raw binary')

            # Entropy analysis (simple)
            entropy = 0.0
            if len(file_data) > 0:
                byte_counts = [0] * 256
                for byte in file_data[:1024]:  # Sample first 1KB
                    byte_counts[byte] += 1

                for count in byte_counts:
                    if count > 0:
                        p = count / 1024
                        entropy -= p * (p.bit_length() - 1) if p > 0 else 0

            findings.append(f'Entropy (sample): {{entropy:.2f}}')
            if entropy > 7.5:
                findings.append('High entropy detected - possibly packed/encrypted')
            elif entropy < 1.0:
                findings.append('Low entropy - likely unprocessed data')

            # String analysis
            strings = []
            current_string = ''
            for byte in file_data[:2048]:  # Sample first 2KB
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ''

            findings.append(f'Printable strings found: {{len(strings)}}')

            # Suspicious indicators
            suspicious_strings = ['debug', 'test', 'password', 'admin', 'license', 'trial']
            found_suspicious = [s for s in strings if any(sus in s.lower() for sus in suspicious_strings)]
            if found_suspicious:
                findings.append(f'Suspicious strings detected: {{len(found_suspicious)}}')

        except Exception as e:
            findings.append(f'Analysis error: {{str(e)}}')

        return {{
            'type': 'binary_analysis',
            'status': 'completed',
            'findings': findings
        }}

    def _detect_packers(self, binary_path: str) -> Dict[str, Any]:
        \"\"\"Detect packers and protectors.\"\"\"
        packer_signatures = {{
            b'UPX!': 'UPX',
            b'ASPack': 'ASPack',
            b'PECompact': 'PECompact',
            b'Themida': 'Themida'
        }}

        detected = []
        with open(binary_path, 'rb') as f:
            header = f.read(8192)
            for sig, name in packer_signatures.items():
                if sig in header:
                    detected.append(name)

        return {{
            'detected': len(detected) > 0,
            'packers': detected
        }}

    def _analyze_network_behavior(self, binary_path: str) -> Dict[str, Any]:
        \"\"\"Analyze potential network behavior.\"\"\"
        # Placeholder for network analysis
        return {{
            'type': 'network_analysis',
            'status': 'completed',
            'findings': ['Network analysis placeholder']
        }}

    def _scan_vulnerabilities(self, binary_path: str) -> List[Dict[str, Any]]:
        \"\"\"Scan for potential vulnerabilities.\"\"\"
        # Placeholder for vulnerability scanning
        return [{{
            'type': 'placeholder',
            'severity': 'info',
            'description': 'Vulnerability scanning placeholder'
        }}]

    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        \"\"\"
        Execute the main plugin functionality.

        Returns:
            dict: Execution results
        \"\"\"
        logger.debug(f"Plugin {{self.name}} execute called with args: {{args}}, kwargs: {{kwargs}}")

        try:
            # Extract binary path from args or kwargs
            binary_path = None
            if args and isinstance(args[0], str):
                binary_path = args[0]
            elif 'binary_path' in kwargs:
                binary_path = kwargs['binary_path']
            elif 'file_path' in kwargs:
                binary_path = kwargs['file_path']

            # Validate binary if provided
            if binary_path:
                is_valid, error_msg = self.validate_binary(binary_path)
                if not is_valid:
                    return {{
                        'status': 'error',
                        'message': f'Binary validation failed: {{error_msg}}',
                        'data': {{}}
                    }}

            # Perform actual analysis
            analysis_results = self._perform_analysis(binary_path, *args, **kwargs)

            result = {{
                'status': 'success',
                'message': f'{{self.name}} executed successfully',
                'data': analysis_results,
                'execution_time': analysis_results.get('execution_time', 0),
                'binary_analyzed': binary_path
            }}

            logger.info(f"{{self.name}} plugin executed successfully")
            return result

        except Exception as e:
            logger.error(f"{{self.name}} plugin execution failed: {{e}}")
            return {{
                'status': 'error',
                'message': str(e),
                'data': {{}},
                'traceback': traceback.format_exc()
            }}

    def analyze(self, binary_path: str) -> List[str]:
        \"\"\"
        Analyze method for compatibility with plugin system.

        Args:
            binary_path: Path to binary file

        Returns:
            List of analysis results as strings
        \"\"\"
        result = self.execute(binary_path)

        if result['status'] == 'success':
            output = [f"Analysis completed for: {{binary_path}}"]
            data = result.get('data', {{}})

            # Format file info
            if 'file_info' in data:
                info = data['file_info']
                output.append(f"File: {{info['name']}} ({{info['size']}} bytes)")
                output.append(f"SHA256: {{info['sha256']}}")

            # Format analysis results
            for key, value in data.items():
                if key not in ['file_info', 'execution_time', 'analysis_timestamp']:
                    output.append(f"{{key}}: {{value}}")

            output.append(f"Execution time: {{data.get('execution_time', 0):.2f}}s")
            return output
        else:
            return [f"Analysis failed: {{result['message']}}"]

    def cleanup(self) -> bool:
        \"\"\"
        Cleanup plugin resources.

        Returns:
            bool: True if cleanup successful
        \"\"\"
        try:
            # Clean up temporary files
            for temp_file in self.temp_files[:]:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        logger.debug(f"Removed temporary file: {{temp_file}}")
                        self.temp_files.remove(temp_file)
                except Exception as e:
                    logger.warning(f"Failed to remove temp file {{temp_file}}: {{e}}")

            # Clear cache
            self.cache.clear()
            logger.debug(f"Cleared {{self.name}} plugin cache")

            # Close any open handles
            for handle in self.open_handles[:]:
                try:
                    handle.close()
                    self.open_handles.remove(handle)
                except Exception as e:
                    logger.warning(f"Failed to close handle: {{e}}")

            # Reset statistics
            self.analysis_count = 0
            self.last_analysis = None

            logger.info(f"{{self.name}} plugin cleaned up successfully")
            return True
        except Exception as e:
            logger.error(f"{{self.name}} plugin cleanup failed: {{e}}")
            return False

# Plugin entry point
def create_plugin():
    \"\"\"Factory function to create plugin instance.\"\"\"
    return {plugin_name.replace(' ', '')}Plugin()

def register():
    \"\"\"Register function for plugin system compatibility.\"\"\"
    return create_plugin()

# Plugin metadata
PLUGIN_INFO = {{
    'name': '{plugin_name}',
    'version': '1.0.0',
    'description': 'Auto-generated {plugin_type.lower()}',
    'author': '{author}',
    'type': '{plugin_type.lower()}',
    'entry_point': 'create_plugin',
    'categories': ['{plugin_type.lower()}'],
    'supported_formats': ['PE', 'ELF', 'Mach-O', 'Raw']
}}

if __name__ == '__main__':
    # Test the plugin
    plugin = create_plugin()
    print(f"Plugin: {{plugin.name}} v{{plugin.version}}")
    print(f"Description: {{plugin.description}}")
    print(f"Author: {{plugin.author}}")
    print(f"\\nTesting plugin functionality...")

    # Test with a dummy file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tf:
        tf.write(b'MZ' + b'\\x00' * 100)  # Simple PE header
        test_file = tf.name

    # Test validation
    is_valid, msg = plugin.validate_binary(test_file)
    print(f"Validation: {{is_valid}} - {{msg}}")

    # Test execution
    result = plugin.execute(test_file)
    print(f"Execution status: {{result['status']}}")
    print(f"Message: {{result['message']}}")

    # Test analyze method
    analysis = plugin.analyze(test_file)
    for line in analysis:
        print(f"  {{line}}")

    # Cleanup
    plugin.cleanup()
    os.unlink(test_file)
"""

            # Save template file
            try:
                filename = f"{plugin_name.replace(' ', '_').lower()}_plugin.py"
                file_path = os.path.join(self.plugins_dir, filename)

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(template_code)

                QMessageBox.information(
                    self,
                    "Template Created",
                    f"Plugin template created successfully:\n{file_path}\n\n"
                    "You can now edit the template to implement your plugin functionality.",
                )

                self.load_installed_plugins()  # Refresh list

            except Exception as e:
                logger.error("Exception in plugin_manager_dialog: %s", e)
                QMessageBox.critical(self, "Error", f"Failed to create template: {e!s}")

        def browse_test_plugin(self):
            """Browse for a plugin file to test."""
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Plugin to Test",
                self.plugins_dir,
                "Python Files (*.py);;All Files (*)",
            )

            if file_path:
                self.test_file_edit.setText(file_path)

        def test_plugin(self):
            """Test the selected plugin."""
            plugin_file = self.test_file_edit.text().strip()
            if not plugin_file:
                QMessageBox.warning(self, "Warning", "Please select a plugin file to test")
                return

            if not os.path.exists(plugin_file):
                QMessageBox.critical(self, "Error", "Selected plugin file does not exist")
                return

            self.test_output.clear()
            self.test_output.append("Testing plugin...\n")

            try:
                # Basic syntax check
                with open(plugin_file, encoding="utf-8") as f:
                    content = f.read()

                # Try to compile the code
                compile(content, plugin_file, "exec")
                self.test_output.append("✓ Syntax check passed")

                # Check for required components
                if "class " in content and "Plugin" in content:
                    self.test_output.append("✓ Plugin class found")
                else:
                    self.test_output.append("⚠ Warning: No plugin class found")

                if "def execute(" in content:
                    self.test_output.append("✓ Execute method found")
                else:
                    self.test_output.append("⚠ Warning: No execute method found")

                if "PLUGIN_INFO" in content:
                    self.test_output.append("✓ Plugin metadata found")
                else:
                    self.test_output.append("⚠ Warning: No plugin metadata found")

                self.test_output.append("\n✅ Plugin test completed successfully")

            except SyntaxError as e:
                logger.error("SyntaxError in plugin_manager_dialog: %s", e)
                self.test_output.append(f"❌ Syntax error: {e}")
            except Exception as e:
                logger.error("Exception in plugin_manager_dialog: %s", e)
                self.test_output.append(f"❌ Test failed: {e}")

        def refresh_plugins(self):
            """Refresh both installed and available plugin lists."""
            self.load_installed_plugins()
            self.load_available_plugins()

        def refresh_available_plugins(self):
            """Refresh the available plugins list."""
            self.load_available_plugins()

        def exec_(self):
            """Execute dialog."""
            return 0 if not HAS_PYQT else super().exec()
