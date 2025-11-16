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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import shutil
import zipfile
from pathlib import Path

# Optional imports with graceful fallbacks
from intellicrack.handlers.pyqt6_handler import (
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
    QSpinBox,
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
        """Fallback class for plugin installation thread when PyQt6 is not available.

        Provides a minimal implementation to prevent import errors in non-GUI environments.
        """

    class PluginManagerDialog:
        """Fallback class for plugin manager dialog when PyQt6 is not available.

        Provides minimal interface methods to allow code to run without PyQt6.
        """

        def __init__(self, parent: object | None = None) -> None:
            """Initialize fallback plugin manager dialog for non-GUI environments."""
            self.parent = parent

            # Initialize UI attributes
            self.author_edit = None
            self.auto_enable = None
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

        def show(self) -> None:
            """Show the dialog (no-op when PyQt6 is not available)."""

        def exec_(self) -> int:
            """Execute the dialog modally (no-op when PyQt6 is not available).

            Returns:
                int: Always returns 0

            """
            return 0

        def exec(self) -> int:
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

        def __init__(self, plugin_path: str, install_dir: str) -> None:
            """Initialize plugin installation thread with source path and destination directory."""
            super().__init__()
            self.plugin_path = plugin_path
            self.install_dir = install_dir

        def run(self) -> None:
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

        def __init__(self, parent: object | None = None, app_context: object | None = None) -> None:
            """Initialize plugin manager dialog with plugin discovery and management capabilities."""
            super().__init__(parent)
            self.setWindowTitle("Plugin Manager")
            self.setMinimumSize(900, 600)

            # App context
            self.app_context = app_context

            # Plugin directories
            self.plugins_dir = os.path.join(str(Path.cwd()), "plugins")
            self.temp_dir = os.path.join(str(Path.cwd()), "temp", "plugins")
            os.makedirs(self.plugins_dir, exist_ok=True)
            os.makedirs(self.temp_dir, exist_ok=True)

            # Plugin repositories
            self.repositories = {
                "Official Repository": "https://api.github.com/repos/intellicrack/plugins/contents",
                "Community Repository": "https://api.github.com/repos/intellicrack-community/plugins/contents",
                "Local Repository": self.plugins_dir,
            }

            # Plugin management
            self.installed_plugins = {}
            self.plugin_categories = ["Analysis", "Exploitation", "Network", "UI", "Utilities", "Tools"]
            self.plugin_configs = {}

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
            if hasattr(self.app_context, "config") and self.app_context.config.get("plugin_auto_update", True):
                QTimer.singleShot(2000, self.check_for_updates)

            logger.info("Plugin Manager Dialog initialized")

            # Show welcome message for first time users
            if not hasattr(self.app_context, "plugin_manager_shown_before"):
                self.show_welcome_message()
                if hasattr(self.app_context, "config"):
                    self.app_context.config["plugin_manager_shown_before"] = True

        def setup_ui(self) -> None:
            """Set up the user interface."""
            self.setWindowTitle("Plugin Manager")
            self.setModal(True)
            self.resize(800, 600)

            layout = QVBoxLayout(self)

            # Create tab widget
            tab_widget = QTabWidget()

            # My plugins tab (renamed from "Installed Plugins")
            installed_tab = QWidget()
            self.setup_installed_tab(installed_tab)
            tab_widget.addTab(installed_tab, "My Plugins")

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

        def setup_connections(self) -> None:
            """Set up signal-slot connections."""
            # Repository selection changes
            if hasattr(self, "repo_combo"):
                self.repo_combo.currentTextChanged.connect(self.on_repository_changed)

            # Auto-refresh timer
            if hasattr(self, "auto_refresh_timer"):
                if hasattr(self.app_context, "config") and self.app_context.config.get("plugin_auto_refresh", False):
                    self.auto_refresh_timer.start(300000)  # 5 minutes

        def on_repository_changed(self, repository_name: str) -> None:
            """Handle repository selection change."""
            try:
                # Repository change handled - available plugins functionality removed
                pass
            except Exception as e:
                logger.error(f"Failed to load repository {repository_name}: {e}")

        def auto_refresh_plugins(self) -> None:
            """Auto-refresh plugin lists."""
            try:
                self.refresh_plugin_lists()
                logger.debug("Auto-refreshed plugin lists")
            except Exception as e:
                logger.warning(f"Auto-refresh failed: {e}")

        def refresh_plugin_lists(self) -> None:
            """Refresh installed plugin lists."""
            try:
                self.load_installed_plugins()
            except Exception as e:
                logger.error(f"Failed to refresh plugin lists: {e}")

        def check_for_updates(self) -> None:
            """Check for plugin updates."""
            try:
                from packaging import version

                logger.debug("Checking for plugin updates...")
                updates_available = 0
                update_details = []

                # Get list of installed plugins
                if not hasattr(self, "installed_plugins"):
                    self.load_installed_plugins()

                # Check each installed plugin for updates
                for plugin_info in self.installed_plugins:
                    try:
                        plugin_name = plugin_info.get("name", "")
                        current_version = plugin_info.get("version", "1.0.0")

                        # Try to determine repository URL from plugin metadata or use defaults
                        repo_url = self._get_plugin_repository_url(plugin_info)

                        if repo_url:
                            logger.debug(f"Checking updates for {plugin_name} from {repo_url}")

                            # Fetch latest version information from repository
                            latest_version_info = self._fetch_latest_version(repo_url, plugin_name)

                            if latest_version_info:
                                latest_version = latest_version_info.get("version", current_version)

                                # Compare versions using semantic versioning
                                try:
                                    if version.parse(latest_version) > version.parse(current_version):
                                        updates_available += 1
                                        update_details.append(
                                            {
                                                "name": plugin_name,
                                                "current": current_version,
                                                "latest": latest_version,
                                                "description": latest_version_info.get("description", ""),
                                                "url": repo_url,
                                            },
                                        )
                                        logger.info(f"Update available for {plugin_name}: {current_version} -> {latest_version}")
                                except Exception as version_error:
                                    logger.debug(f"Version comparison failed for {plugin_name}: {version_error}")

                    except Exception as plugin_error:
                        logger.debug(f"Failed to check updates for plugin {plugin_name}: {plugin_error}")

                # Show results to user
                if updates_available > 0:
                    update_message = f"{updates_available} plugin update(s) available:\n\n"
                    for update in update_details[:5]:  # Limit to first 5 for readability
                        update_message += f" {update['name']}: {update['current']} → {update['latest']}\n"

                    if len(update_details) > 5:
                        update_message += f"... and {len(update_details) - 5} more updates\n"

                    update_message += "\nUse the repository tab to update plugins."

                    QMessageBox.information(self, "Updates Available", update_message)
                else:
                    QMessageBox.information(self, "Updates Check", "All plugins are up to date!")

            except Exception as e:
                logger.warning(f"Update check failed: {e}")

        def _get_plugin_repository_url(self, plugin_info: dict) -> str | None:
            """Determine repository URL for a plugin."""
            try:
                plugin_name = plugin_info.get("name", "")
                plugin_path = plugin_info.get("path", "")

                # Try to read repository URL from plugin metadata
                if plugin_path.endswith(".py") and os.path.exists(plugin_path):
                    with open(plugin_path, encoding="utf-8") as f:
                        content = f.read()

                    # Look for repository URL in comments
                    lines = content.split("\n")
                    for line in lines[:30]:  # Check first 30 lines
                        line = line.strip()
                        if line.startswith("# Repository:") or line.startswith("# Repo:") or line.startswith("# URL:"):
                            return line.split(":", 1)[1].strip()

                # Default repository URLs for known plugins
                default_repos = {
                    "intellicrack-plugins": "https://api.github.com/repos/intellicrack/plugins",
                    "community-plugins": "https://api.github.com/repos/intellicrack-community/plugins",
                }

                # Check if plugin name matches any default repository
                for repo_name, repo_url in default_repos.items():
                    if repo_name in plugin_name.lower():
                        return repo_url

                # Fallback to main Intellicrack plugin repository
                return "https://api.github.com/repos/intellicrack/community-plugins"

            except Exception as e:
                logger.debug(f"Failed to determine repository URL for plugin {plugin_info.get('name', 'unknown')}: {e}")
                return None

        def _fetch_latest_version(self, repo_url: str, plugin_name: str) -> dict | None:
            """Fetch latest version information from repository."""
            try:
                import requests

                # Try different API endpoints based on repository type
                if "github.com" in repo_url:
                    # GitHub API approach
                    if not repo_url.startswith("https://api.github.com"):
                        # Convert regular GitHub URL to API URL
                        repo_url = repo_url.replace("github.com/", "api.github.com/repos/")

                    # Try to get latest release
                    release_url = f"{repo_url}/releases/latest"
                    response = requests.get(release_url, timeout=10)

                    if response.status_code == 200:
                        release_data = response.json()
                        return {
                            "version": release_data.get("tag_name", "").lstrip("v"),
                            "description": release_data.get("name", ""),
                            "published_at": release_data.get("published_at", ""),
                        }

                    # Fallback: try to get tags if no releases
                    tags_url = f"{repo_url}/tags"
                    response = requests.get(tags_url, timeout=10)

                    if response.status_code == 200:
                        tags_data = response.json()
                        if tags_data:
                            latest_tag = tags_data[0]
                            return {
                                "version": latest_tag.get("name", "").lstrip("v"),
                                "description": f"Latest tag: {latest_tag.get('name', '')}",
                                "published_at": "",
                            }

                    # Fallback: try to get plugin manifest file
                    manifest_url = f"{repo_url.replace('/api.github.com/repos/', '/raw.githubusercontent.com/')}/main/plugins/{plugin_name}/manifest.json"
                    response = requests.get(manifest_url, timeout=10)

                    if response.status_code == 200:
                        manifest_data = response.json()
                        return {
                            "version": manifest_data.get("version", "1.0.0"),
                            "description": manifest_data.get("description", ""),
                            "published_at": manifest_data.get("updated", ""),
                        }

                else:
                    # Generic approach for other repository types
                    # Try to fetch a manifest.json or version.json file
                    for file_name in ["manifest.json", "version.json", "plugin.json"]:
                        try:
                            version_url = f"{repo_url.rstrip('/')}/{plugin_name}/{file_name}"
                            response = requests.get(version_url, timeout=10)

                            if response.status_code == 200:
                                version_data = response.json()
                                return {
                                    "version": version_data.get("version", "1.0.0"),
                                    "description": version_data.get("description", ""),
                                    "published_at": version_data.get("updated", ""),
                                }
                        except Exception as file_error:
                            logger.debug(f"Failed to fetch {file_name} for {plugin_name}: {file_error}")

                return None

            except requests.RequestError as req_error:
                logger.debug(f"Network error fetching version for {plugin_name}: {req_error}")
                return None
            except Exception as e:
                logger.debug(f"Failed to fetch latest version for {plugin_name}: {e}")
                return None

        def show_welcome_message(self) -> None:
            """Show welcome message for first-time users."""
            welcome_msg = QMessageBox(self)
            welcome_msg.setWindowTitle("Welcome to Plugin Manager")
            welcome_msg.setIcon(QMessageBox.Information)
            welcome_msg.setText(
                "Welcome to the Intellicrack Plugin Manager!\n\n"
                "Here you can:\n"
                " View and manage installed plugins\n"
                " Browse and install plugins from repositories\n"
                " Install plugins from local files\n"
                " Create and test your own plugins\n\n"
                "Get started by exploring the available tabs above.",
            )
            welcome_msg.addButton("Get Started", QMessageBox.AcceptRole)
            welcome_msg.exec()

        def load_settings(self) -> None:
            """Load plugin manager settings."""
            try:
                if hasattr(self.app_context, "config"):
                    config = self.app_context.config

                    # Load plugin configurations
                    if "plugin_configs" in config:
                        self.plugin_configs = config["plugin_configs"].copy()

                    # Load repository settings
                    if "plugin_repositories" in config:
                        self.repositories.update(config["plugin_repositories"])

            except Exception as e:
                logger.debug(f"Failed to load plugin settings: {e}")

        def setup_installed_tab(self, tab: object) -> None:
            """Set up the installed plugins tab."""
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

        def setup_install_tab(self, tab: object) -> None:
            """Set up the install from file tab."""
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

        def setup_development_tab(self, tab: object) -> None:
            """Set up the plugin development tab."""
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
                ],
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

        def load_installed_plugins(self) -> None:
            """Load list of installed plugins."""
            self.installed_plugins = []
            self.installed_list.clear()

            try:
                if os.path.exists(self.plugins_dir):
                    for item in os.listdir(self.plugins_dir):
                        item_path = os.path.join(self.plugins_dir, item)
                        if Path(item_path).is_dir() or item.endswith(".py"):
                            plugin_info = self.get_plugin_info(item_path)
                            self.installed_plugins.append(plugin_info)

                            list_item = QListWidgetItem(plugin_info["name"])
                            list_item.setData(0, plugin_info)

                            # Color code based on status
                            if plugin_info.get("enabled", True):
                                list_item.setForeground(list_item.foreground())  # Default color
                            else:
                                from intellicrack.handlers.pyqt6_handler import QColor

                                list_item.setForeground(QColor(128, 128, 128))  # Gray for disabled

                            self.installed_list.addItem(list_item)
            except Exception as e:
                logger.error(f"Error loading installed plugins: {e}")

        def get_plugin_info(self, plugin_path: str) -> dict:
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

        def on_installed_selection_changed(self) -> None:
            """Handle selection change in installed plugins list."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                info_text = f"""Plugin: {plugin_info["name"]}
Version: {plugin_info.get("version", "Unknown")}
Type: {plugin_info["type"]}
Path: {plugin_info["path"]}
Status: {"Enabled" if plugin_info.get("enabled", True) else "Disabled"}

Description: {plugin_info.get("description", "No description available")}"""
                self.plugin_info.setPlainText(info_text)
            else:
                self.plugin_info.clear()

        def on_available_selection_changed(self) -> None:
            """Handle selection change in available plugins list - functionality removed."""

        def enable_selected_plugin(self) -> None:
            """Enable the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                plugin_info["enabled"] = True
                current_item.setData(0, plugin_info)
                current_item.setForeground(current_item.foreground())  # Reset to default color
                self.on_installed_selection_changed()  # Refresh info display
                QMessageBox.information(self, "Success", f"Plugin '{plugin_info['name']}' enabled")

        def disable_selected_plugin(self) -> None:
            """Disable the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                plugin_info["enabled"] = False
                current_item.setData(0, plugin_info)
                from intellicrack.handlers.pyqt6_handler import QColor

                current_item.setForeground(QColor(128, 128, 128))  # Gray out
                self.on_installed_selection_changed()  # Refresh info display
                QMessageBox.information(self, "Success", f"Plugin '{plugin_info['name']}' disabled")

        def remove_selected_plugin(self) -> None:
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
                        elif Path(plugin_info["path"]).is_dir():
                            shutil.rmtree(plugin_info["path"])

                        self.load_installed_plugins()  # Refresh list
                        QMessageBox.information(self, "Success", "Plugin removed successfully")
                    except Exception as e:
                        logger.error("Exception in plugin_manager_dialog: %s", e)
                        QMessageBox.critical(self, "Error", f"Failed to remove plugin: {e!s}")

        def configure_selected_plugin(self) -> None:
            """Configure the selected plugin."""
            current_item = self.installed_list.currentItem()
            if current_item:
                plugin_info = current_item.data(0)
                plugin_name = plugin_info["name"]

                # Create configuration dialog
                config_dialog = QDialog(self)
                config_dialog.setWindowTitle(f"Configure {plugin_name}")
                config_dialog.setModal(True)
                config_dialog.resize(500, 400)

                layout = QVBoxLayout(config_dialog)

                # Configuration form
                form_group = QGroupBox("Plugin Configuration")
                form_layout = QFormLayout(form_group)

                # Load existing configuration
                plugin_config = self.plugin_configs.get(plugin_name, {})
                config_widgets = {}

                # Common configuration options
                config_options = [
                    ("enabled", "Enabled", "checkbox", plugin_config.get("enabled", True)),
                    ("auto_update", "Auto Update", "checkbox", plugin_config.get("auto_update", True)),
                    ("max_file_size", "Max File Size (MB)", "spinbox", plugin_config.get("max_file_size", 100)),
                    ("timeout", "Timeout (seconds)", "spinbox", plugin_config.get("timeout", 30)),
                    ("temp_dir", "Temporary Directory", "text", plugin_config.get("temp_dir", self.temp_dir)),
                    ("log_level", "Log Level", "combo", plugin_config.get("log_level", "INFO")),
                ]

                # Add plugin-specific options based on category
                category = plugin_info.get("category", "Utilities").lower()
                if category == "analysis":
                    config_options.extend(
                        [
                            ("deep_scan", "Deep Analysis", "checkbox", plugin_config.get("deep_scan", False)),
                            ("entropy_threshold", "Entropy Threshold", "spinbox", plugin_config.get("entropy_threshold", 7.5)),
                            ("scan_sections", "Scan All Sections", "checkbox", plugin_config.get("scan_sections", True)),
                        ],
                    )
                elif category == "exploitation":
                    config_options.extend(
                        [
                            ("safe_mode", "Safe Mode", "checkbox", plugin_config.get("safe_mode", True)),
                            ("backup_target", "Backup Target", "checkbox", plugin_config.get("backup_target", True)),
                            ("max_attempts", "Max Attempts", "spinbox", plugin_config.get("max_attempts", 3)),
                        ],
                    )
                elif category == "network":
                    config_options.extend(
                        [
                            ("capture_packets", "Capture Packets", "checkbox", plugin_config.get("capture_packets", False)),
                            ("interface", "Network Interface", "text", plugin_config.get("interface", "auto")),
                            ("port_range", "Port Range", "text", plugin_config.get("port_range", "1-65535")),
                        ],
                    )

                # Create widgets for each option
                for key, label, widget_type, default_value in config_options:
                    if widget_type == "checkbox":
                        widget = QCheckBox()
                        widget.setChecked(bool(default_value))
                    elif widget_type == "spinbox":
                        widget = QSpinBox()
                        widget.setRange(0, 99999)
                        widget.setValue(int(default_value) if isinstance(default_value, (int, float)) else 0)
                    elif widget_type == "combo":
                        widget = QComboBox()
                        if key == "log_level":
                            widget.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
                            if default_value in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
                                widget.setCurrentText(str(default_value))
                    else:  # text
                        widget = QLineEdit()
                        widget.setText(str(default_value) if default_value else "")

                    config_widgets[key] = widget
                    form_layout.addRow(label + ":", widget)

                layout.addWidget(form_group)

                # Advanced settings
                advanced_group = QGroupBox("Advanced Settings")
                advanced_layout = QVBoxLayout(advanced_group)

                # Custom arguments
                advanced_layout.addWidget(QLabel("Custom Arguments:"))
                custom_args_edit = QTextEdit()
                custom_args_edit.setMaximumHeight(100)
                custom_args_edit.setPlainText(plugin_config.get("custom_args", ""))
                advanced_layout.addWidget(custom_args_edit)
                config_widgets["custom_args"] = custom_args_edit

                layout.addWidget(advanced_group)

                # Plugin information
                info_group = QGroupBox("Plugin Information")
                info_layout = QVBoxLayout(info_group)
                info_text = QTextEdit()
                info_text.setReadOnly(True)
                info_text.setMaximumHeight(100)

                plugin_info_text = f"""Name: {plugin_info["name"]}
Version: {plugin_info.get("version", "Unknown")}
Author: {plugin_info.get("author", "Unknown")}
Type: {plugin_info.get("type", "file")}
Path: {plugin_info.get("path", "Unknown")}"""
                info_text.setPlainText(plugin_info_text)
                info_layout.addWidget(info_text)
                layout.addWidget(info_group)

                # Dialog buttons
                button_layout = QHBoxLayout()

                # Reset to defaults button
                reset_btn = QPushButton("Reset to Defaults")

                def reset_defaults() -> None:
                    for key, _label, widget_type, default_value in config_options:
                        widget = config_widgets[key]
                        if widget_type == "checkbox":
                            widget.setChecked(bool(default_value))
                        elif widget_type == "spinbox":
                            widget.setValue(int(default_value) if isinstance(default_value, (int, float)) else 0)
                        elif widget_type == "combo":
                            if isinstance(default_value, str):
                                widget.setCurrentText(default_value)
                        else:  # text
                            widget.setText(str(default_value) if default_value else "")
                    custom_args_edit.clear()

                reset_btn.clicked.connect(reset_defaults)
                button_layout.addWidget(reset_btn)

                button_layout.addStretch()

                # OK/Cancel buttons
                ok_btn = QPushButton("OK")
                cancel_btn = QPushButton("Cancel")

                def save_configuration() -> None:
                    # Save configuration
                    new_config = {}
                    for key, widget in config_widgets.items():
                        if isinstance(widget, QCheckBox):
                            new_config[key] = widget.isChecked()
                        elif isinstance(widget, QSpinBox):
                            new_config[key] = widget.value()
                        elif isinstance(widget, QComboBox):
                            new_config[key] = widget.currentText()
                        elif isinstance(widget, QLineEdit):
                            new_config[key] = widget.text()
                        elif isinstance(widget, QTextEdit):
                            new_config[key] = widget.toPlainText()

                    # Store configuration
                    self.plugin_configs[plugin_name] = new_config

                    # Save to file if app_context is available
                    if hasattr(self.app_context, "config"):
                        if "plugin_configs" not in self.app_context.config:
                            self.app_context.config["plugin_configs"] = {}
                        self.app_context.config["plugin_configs"][plugin_name] = new_config

                        # Save configuration to file
                        try:
                            config_file = os.path.join(self.plugins_dir, f"{plugin_name}_config.json")
                            import json

                            with open(config_file, "w") as f:
                                json.dump(new_config, f, indent=2)
                        except Exception as e:
                            logger.warning(f"Failed to save plugin configuration: {e}")

                    config_dialog.accept()
                    QMessageBox.information(self, "Success", f"Configuration saved for {plugin_name}")

                ok_btn.clicked.connect(save_configuration)
                cancel_btn.clicked.connect(config_dialog.reject)

                button_layout.addWidget(ok_btn)
                button_layout.addWidget(cancel_btn)

                layout.addLayout(button_layout)

                # Show dialog
                config_dialog.exec()

        def install_selected_plugin(self) -> None:
            """Install the selected available plugin - functionality removed."""
            QMessageBox.information(self, "Information", "Available plugins functionality has been removed.")

        def _check_dependencies(self, dependencies: list) -> list:
            """Check which dependencies are missing."""
            missing = []

            for dep in dependencies:
                try:
                    # Try to import the dependency
                    if dep == "numpy":
                        import numpy as np

                        _ = np.__name__  # Verify numpy scientific computing library is available
                    elif dep == "scipy":
                        import scipy

                        _ = scipy.__name__  # Verify scipy scientific computing library is available
                    elif dep == "pefile":
                        import pefile

                        _ = pefile.__name__  # Verify pefile PE analysis library is available
                    elif dep == "yara-python":
                        import yara

                        _ = yara.__name__  # Verify yara pattern matching engine is available
                    elif dep == "frida":
                        import frida

                        _ = frida.__name__  # Verify frida dynamic instrumentation toolkit is available
                    elif dep == "psutil":
                        import psutil

                        _ = psutil.__name__  # Verify psutil system monitoring library is available
                    elif dep == "capstone":
                        import capstone

                        _ = capstone.__name__  # Verify capstone disassembly engine is available
                    elif dep == "unicorn":
                        import unicorn

                        _ = unicorn.__name__  # Verify unicorn CPU emulator engine is available
                    elif dep == "scapy":
                        import scapy

                        _ = scapy.__name__  # Verify scapy network packet manipulation library is available
                    elif dep == "pyshark":
                        import pyshark

                        _ = pyshark.__name__  # Verify pyshark Wireshark packet capture library is available
                    elif dep == "regex":
                        import regex

                        _ = regex.__name__  # Verify regex enhanced regular expression library is available
                    # Add more dependency checks as needed
                except ImportError:
                    missing.append(dep)
                except Exception:
                    missing.append(dep)

            return missing

        def _start_remote_plugin_installation(self, plugin_info: dict) -> None:
            """Start the remote plugin installation process."""
            plugin_name = plugin_info["name"]
            source = plugin_info.get("source", "remote")

            if source == "local":
                # Copy local plugin
                src_path = plugin_info.get("install_path")
                if not src_path or not os.path.exists(src_path):
                    QMessageBox.critical(self, "Error", "Local plugin file not found")
                    return

                dest_name = f"{plugin_name.lower().replace(' ', '_')}.py"
                dest_path = os.path.join(self.plugins_dir, dest_name)

                try:
                    if os.path.isfile(src_path):
                        shutil.copy2(src_path, dest_path)
                    else:
                        # Copy directory
                        dest_dir = os.path.join(self.plugins_dir, plugin_name.lower().replace(" ", "_"))
                        if os.path.exists(dest_dir):
                            shutil.rmtree(dest_dir)
                        shutil.copytree(src_path, dest_dir)

                    QMessageBox.information(self, "Success", f"Plugin '{plugin_name}' installed successfully")
                    self.load_installed_plugins()

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to install plugin: {e!s}")

            else:
                # Download and install remote plugin
                download_url = plugin_info.get("download_url")

                if not download_url:
                    # Create a realistic plugin file for fallback plugins
                    self._create_fallback_plugin(plugin_info)
                    return

                # Create installation dialog with progress
                install_dialog = QDialog(self)
                install_dialog.setWindowTitle(f"Installing {plugin_name}")
                install_dialog.setModal(True)
                install_dialog.resize(400, 200)

                layout = QVBoxLayout(install_dialog)

                status_label = QLabel(f"Preparing to download {plugin_name}...")
                layout.addWidget(status_label)

                progress_bar = QProgressBar()
                layout.addWidget(progress_bar)

                log_text = QTextEdit()
                log_text.setMaximumHeight(100)
                log_text.setReadOnly(True)
                layout.addWidget(log_text)

                button_layout = QHBoxLayout()
                cancel_btn = QPushButton("Cancel")
                button_layout.addWidget(cancel_btn)
                button_layout.addStretch()
                layout.addLayout(button_layout)

                # Download and install remote plugin
                def perform_installation() -> None:
                    try:
                        import requests
                        from requests.exceptions import ConnectionError as RequestsConnectionError
                        from requests.exceptions import RequestException, Timeout

                        status_label.setText("Downloading plugin...")
                        log_text.append(f"Downloading from: {download_url}")

                        try:
                            response = requests.get(download_url, timeout=30, stream=True)
                            response.raise_for_status()
                            progress_bar.setValue(25)

                            total_size = int(response.headers.get("content-length", 0))
                            downloaded = 0
                            chunk_size = 8192
                            temp_file = os.path.join(self.temp_dir, f"{plugin_name}_download.zip")

                            with open(temp_file, "wb") as f:
                                for chunk in response.iter_content(chunk_size=chunk_size):
                                    if chunk:
                                        f.write(chunk)
                                        downloaded += len(chunk)
                                        if total_size:
                                            progress = 25 + int((downloaded / total_size) * 25)
                                            progress_bar.setValue(min(progress, 49))
                                        log_text.append(f"Downloaded: {downloaded} bytes")

                            progress_bar.setValue(50)
                            status_label.setText("Extracting plugin files...")
                            log_text.append("Extracting plugin archive...")

                            extract_dir = os.path.join(self.plugins_dir, plugin_name.lower().replace(" ", "_"))
                            os.makedirs(extract_dir, exist_ok=True)

                            if temp_file.endswith(".zip"):
                                with zipfile.ZipFile(temp_file, "r") as zip_ref:
                                    zip_ref.extractall(extract_dir)
                            else:
                                shutil.copy2(temp_file, extract_dir)

                            progress_bar.setValue(75)
                            status_label.setText("Validating plugin...")
                            log_text.append("Validating plugin integrity...")

                            if os.path.exists(extract_dir):
                                plugin_files = os.listdir(extract_dir)
                                if any(f.endswith(".py") for f in plugin_files):
                                    progress_bar.setValue(100)
                                    status_label.setText("Installation complete!")
                                    log_text.append(f"Plugin '{plugin_name}' installed successfully")
                                else:
                                    status_label.setText("Installation failed!")
                                    log_text.append("ERROR: No valid plugin files found in archive")
                                    return

                            if os.path.exists(temp_file):
                                os.remove(temp_file)

                            cancel_btn.setText("Close")
                            cancel_btn.clicked.disconnect()
                            cancel_btn.clicked.connect(install_dialog.accept)

                            QTimer.singleShot(1000, install_dialog.accept)

                        except (RequestException, Timeout, RequestsConnectionError) as net_error:
                            status_label.setText("Installation failed!")
                            log_text.append(f"Network error: {net_error!s}")
                            progress_bar.setValue(0)
                            logger.error(f"Network error downloading plugin: {net_error}")

                    except Exception as e:
                        status_label.setText("Installation failed!")
                        log_text.append(f"Error: {e!s}")
                        progress_bar.setValue(0)
                        logger.error(f"Plugin installation error: {e}")

                cancel_btn.clicked.connect(install_dialog.reject)

                # Start installation after dialog shows
                QTimer.singleShot(500, perform_installation)

                if install_dialog.exec() == QDialog.Accepted:
                    self.load_installed_plugins()
                    QMessageBox.information(self, "Success", f"Plugin '{plugin_name}' has been installed successfully!")

        def _create_fallback_plugin(self, plugin_info: dict) -> None:
            """Create a realistic plugin file for fallback plugins."""
            plugin_name = plugin_info["name"]
            plugin_version = plugin_info.get("version", "1.0.0")
            plugin_author = plugin_info.get("author", "Unknown")
            plugin_desc = plugin_info.get("description", "No description available")
            plugin_category = plugin_info.get("category", "Utilities")

            # Generate plugin code based on category
            if plugin_category.lower() == "analysis":
                plugin_code = self._generate_analysis_plugin_code(plugin_name, plugin_version, plugin_author, plugin_desc)
            elif plugin_category.lower() == "exploitation":
                plugin_code = self._generate_exploitation_plugin_code(plugin_name, plugin_version, plugin_author, plugin_desc)
            elif plugin_category.lower() == "network":
                plugin_code = self._generate_network_plugin_code(plugin_name, plugin_version, plugin_author, plugin_desc)
            else:
                plugin_code = self._generate_generic_plugin_code(plugin_name, plugin_version, plugin_author, plugin_desc)

            # Save plugin file
            filename = f"{plugin_name.lower().replace(' ', '_').replace('-', '_')}.py"
            filepath = os.path.join(self.plugins_dir, filename)

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(plugin_code)
                logger.info(f"Created fallback plugin: {filepath}")
            except Exception as e:
                logger.error(f"Failed to create fallback plugin: {e}")
                raise

        def _generate_analysis_plugin_code(self, name: str, version: str, author: str, description: str) -> str:
            """Generate analysis plugin code."""
            class_name = name.replace(" ", "").replace("-", "")
            return f'''#!/usr/bin/env python3
"""
{name} - Analysis Plugin for Intellicrack

Author: {author}
Version: {version}
Description: {description}
"""

import os
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class {class_name}Plugin:
    """Advanced binary analysis plugin with entropy detection and pattern matching."""

    def __init__(self):
        self.name = "{name}"
        self.version = "{version}"
        self.description = "{description}"
        self.author = "{author}"
        self.category = "Analysis"

        # Analysis state
        self.app = None
        self.analysis_results = {{}}
        self.signature_db = {{
            'upx': [b'UPX!', b'UPX0', b'UPX1'],
            'aspack': [b'ASPack', b'aPSPack'],
            'pecompact': [b'PECompact'],
            'themida': [b'Themida', b'WinLicense']
        }}

    def initialize(self, app_instance) -> bool:
        """Initialize the plugin with app instance."""
        try:
            self.app = app_instance
            logger.info(f"{{self.name}} plugin initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize {{self.name}}: {{e}}")
            return False

    def analyze_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * (p.bit_length() - 1) if p > 0 else 0

        return entropy

    def detect_packers(self, data: bytes) -> List[str]:
        """Detect known packers and protectors."""
        detected = []

        # Check first 2KB for packer signatures
        header = data[:2048]

        for packer, signatures in self.signature_db.items():
            for sig in signatures:
                if sig in header:
                    detected.append(packer.upper())
                    break

        return detected

    def analyze_sections(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE sections if possible."""
        results = {{
            'sections': [],
            'suspicious_sections': [],
            'entry_point': None
        }}

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Basic PE header check
            if data.startswith(b'MZ'):
                # Look for PE signature
                pe_offset_pos = 60  # 0x3C
                if len(data) > pe_offset_pos + 4:
                    pe_offset = int.from_bytes(data[pe_offset_pos:pe_offset_pos+4], 'little')
                    if pe_offset < len(data) - 4:
                        pe_sig = data[pe_offset:pe_offset+4]
                        if pe_sig == b'PE\\x00\\x00':
                            results['pe_detected'] = True

                            # Extract basic section info (simplified)
                            sections_data = self._extract_pe_sections(data, pe_offset)
                            results.update(sections_data)

        except Exception as e:
            logger.debug(f"Section analysis failed: {{e}}")

        return results

    def _extract_pe_sections(self, data: bytes, pe_offset: int) -> Dict[str, Any]:
        """Extract PE section information."""
        sections = []
        suspicious = []

        try:
            # PE header starts after signature
            pe_header = pe_offset + 4

            # Machine type and section count (simplified extraction)
            if len(data) > pe_header + 6:
                num_sections = int.from_bytes(data[pe_header+2:pe_header+4], 'little')

                # Optional header size
                opt_header_size = int.from_bytes(data[pe_header+16:pe_header+18], 'little')

                # Section table starts after optional header
                section_table = pe_header + 20 + opt_header_size

                for i in range(min(num_sections, 10)):  # Limit to 10 sections
                    section_offset = section_table + (i * 40)
                    if section_offset + 40 > len(data):
                        break

                    # Extract section name (8 bytes)
                    name_bytes = data[section_offset:section_offset+8]
                    name = name_bytes.rstrip(b'\\x00').decode('ascii', errors='ignore')

                    # Virtual size and address
                    virtual_size = int.from_bytes(data[section_offset+8:section_offset+12], 'little')
                    virtual_addr = int.from_bytes(data[section_offset+12:section_offset+16], 'little')
                    raw_size = int.from_bytes(data[section_offset+16:section_offset+20], 'little')
                    raw_addr = int.from_bytes(data[section_offset+20:section_offset+24], 'little')

                    section_info = {{
                        'name': name,
                        'virtual_size': virtual_size,
                        'virtual_address': virtual_addr,
                        'raw_size': raw_size,
                        'raw_address': raw_addr
                    }}

                    sections.append(section_info)

                    # Check for suspicious characteristics
                    if name in ['.upx0', '.upx1', '.aspack', '.themida']:
                        suspicious.append(f"Suspicious section name: {{name}}")

                    if virtual_size > 0 and raw_size == 0:
                        suspicious.append(f"Virtual section detected: {{name}}")

        except Exception as e:
            logger.debug(f"PE section extraction failed: {{e}}")

        return {{
            'sections': sections,
            'suspicious_sections': suspicious
        }}

    def execute(self, binary_path: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute main analysis functionality."""
        logger.info(f"Starting {{self.name}} analysis on: {{binary_path}}")

        if not os.path.exists(binary_path):
            return {{
                'status': 'error',
                'message': f'File not found: {{binary_path}}',
                'data': {{}}
            }}

        try:
            start_time = time.time()

            # Read file data
            with open(binary_path, 'rb') as f:
                file_data = f.read()

            # Basic file info
            file_info = {{
                'size': len(file_data),
                'md5': hashlib.md5(file_data).hexdigest(),
                'sha256': hashlib.sha256(file_data).hexdigest()
            }}

            # Entropy analysis
            entropy = self.analyze_entropy(file_data)

            # Packer detection
            packers = self.detect_packers(file_data)

            # Section analysis
            sections = self.analyze_sections(binary_path)

            # String extraction (sample first 10KB)
            strings = self._extract_strings(file_data[:10240])

            results = {{
                'file_info': file_info,
                'entropy': entropy,
                'packers_detected': packers,
                'sections': sections,
                'strings_found': len(strings),
                'suspicious_strings': [s for s in strings if any(sus in s.lower()
                                     for sus in ['password', 'license', 'trial', 'crack'])],
                'execution_time': time.time() - start_time,
                'findings': []
            }}

            # Generate findings
            findings = []
            if entropy > 7.5:
                findings.append(f"High entropy ({{entropy:.2f}}) - possible packing/encryption")
            if packers:
                findings.append(f"Packers detected: {{', '.join(packers)}}")
            if sections.get('suspicious_sections'):
                findings.extend(sections['suspicious_sections'])

            results['findings'] = findings

            return {{
                'status': 'success',
                'message': f'Analysis completed for {{os.path.basename(binary_path)}}',
                'data': results
            }}

        except Exception as e:
            logger.error(f"Analysis failed: {{e}}")
            return {{
                'status': 'error',
                'message': str(e),
                'data': {{}}
            }}

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current_string = ""

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""

        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)

        return strings

    def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.analysis_results.clear()
            logger.info(f"{{self.name}} plugin cleaned up")
            return True
        except Exception as e:
            logger.error(f"Cleanup failed: {{e}}")
            return False

# Plugin registration
def create_plugin():
    return {class_name}Plugin()

def register():
    return create_plugin()

PLUGIN_INFO = {{
    'name': '{name}',
    'version': '{version}',
    'description': '{description}',
    'author': '{author}',
    'type': 'analysis',
    'entry_point': 'create_plugin',
    'categories': ['Analysis'],
    'supported_formats': ['PE', 'ELF', 'Raw']
}}
'''

        def _generate_exploitation_plugin_code(self, name: str, version: str, author: str, description: str) -> str:
            """Generate exploitation plugin code."""
            class_name = name.replace(" ", "").replace("-", "")
            return f'''#!/usr/bin/env python3
"""
{name} - Exploitation Plugin for Intellicrack

Author: {author}
Version: {version}
Description: {description}
"""

import os
import time
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class {class_name}Plugin:
    """Advanced exploitation plugin for license bypass and code patching."""

    def __init__(self):
        self.name = "{name}"
        self.version = "{version}"
        self.description = "{description}"
        self.author = "{author}"
        self.category = "Exploitation"

        # Exploitation patterns
        self.license_patterns = [
            b'Trial expired', b'Invalid license', b'License not found',
            b'Registration required', b'Please register'
        ]

    def execute(self, binary_path: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute exploitation analysis."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            findings = []
            for pattern in self.license_patterns:
                if pattern in data:
                    findings.append(f"License check pattern found: {{pattern.decode('ascii', errors='ignore')}}")

            return {{
                'status': 'success',
                'message': 'Exploitation analysis completed',
                'data': {{'findings': findings}}
            }}
        except Exception as e:
            return {{'status': 'error', 'message': str(e), 'data': {{}}}}

def create_plugin():
    return {class_name}Plugin()

PLUGIN_INFO = {{
    'name': '{name}',
    'version': '{version}',
    'description': '{description}',
    'author': '{author}',
    'type': 'exploitation'
}}
'''

        def _generate_network_plugin_code(self, name: str, version: str, author: str, description: str) -> str:
            """Generate network plugin code."""
            class_name = name.replace(" ", "").replace("-", "")
            return f'''#!/usr/bin/env python3
"""
{name} - Network Plugin for Intellicrack

Author: {author}
Version: {version}
Description: {description}
"""

import os
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class {class_name}Plugin:
    """Network analysis plugin for communication patterns."""

    def __init__(self):
        self.name = "{name}"
        self.version = "{version}"
        self.description = "{description}"
        self.author = "{author}"
        self.category = "Network"

    def execute(self, binary_path: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute network analysis."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for network indicators
            network_strings = []
            for line in data.split(b'\\x00'):
                line_str = line.decode('ascii', errors='ignore')
                if any(indicator in line_str.lower() for indicator in ['http', 'tcp', 'udp', 'socket']):
                    network_strings.append(line_str.strip())

            return {{
                'status': 'success',
                'message': 'Network analysis completed',
                'data': {{'network_strings': network_strings[:10]}}  # Limit output
            }}
        except Exception as e:
            return {{'status': 'error', 'message': str(e), 'data': {{}}}}

def create_plugin():
    return {class_name}Plugin()

PLUGIN_INFO = {{
    'name': '{name}',
    'version': '{version}',
    'description': '{description}',
    'author': '{author}',
    'type': 'network'
}}
'''

        def _generate_generic_plugin_code(self, name: str, version: str, author: str, description: str) -> str:
            """Generate generic plugin code."""
            class_name = name.replace(" ", "").replace("-", "")
            return f'''#!/usr/bin/env python3
"""
{name} - Generic Plugin for Intellicrack

Author: {author}
Version: {version}
Description: {description}
"""

import os
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class {class_name}Plugin:
    """Provide utility plugin."""

    def __init__(self):
        self.name = "{name}"
        self.version = "{version}"
        self.description = "{description}"
        self.author = "{author}"
        self.category = "Utilities"

    def execute(self, binary_path: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute generic analysis."""
        try:
            file_size = os.path.getsize(binary_path)
            return {{
                'status': 'success',
                'message': 'Generic analysis completed',
                'data': {{'file_size': file_size, 'path': binary_path}}
            }}
        except Exception as e:
            return {{'status': 'error', 'message': str(e), 'data': {{}}}}

def create_plugin():
    return {class_name}Plugin()

PLUGIN_INFO = {{
    'name': '{name}',
    'version': '{version}',
    'description': '{description}',
    'author': '{author}',
    'type': 'generic'
}}
'''

        def preview_selected_plugin(self) -> None:
            """Preview the selected available plugin - functionality removed."""
            QMessageBox.information(self, "Information", "Available plugins functionality has been removed.")

        def _install_from_preview(self, plugin_info: dict, preview_dialog: object) -> None:
            """Install plugin directly from preview dialog - functionality removed."""

        def _generate_preview_analysis_code(self, plugin_name: str) -> str:
            """Generate preview code for analysis plugins."""
            return f'''# {plugin_name} - Analysis Plugin Preview

import hashlib
import logging

class Plugin:
    def __init__(self):
        self.name = "{plugin_name}"

    def analyze_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        # Entropy calculation logic...

    def detect_packers(self, data):
        """Detect known packers"""
        signatures = {{
            'upx': [b'UPX!', b'UPX0'],
            'aspack': [b'ASPack']
        }}
        # Detection logic...

    def execute(self, binary_path):
        """Run analysis function"""
        with open(binary_path, 'rb') as f:
            data = f.read()

        return {{
            'entropy': self.analyze_entropy(data),
            'packers': self.detect_packers(data),
            'file_hash': hashlib.sha256(data).hexdigest()
        }}

# ... (additional methods)'''

        def _generate_preview_exploitation_code(self, plugin_name: str) -> str:
            """Generate preview code for exploitation plugins."""
            return f'''# {plugin_name} - Exploitation Plugin Preview

import logging

class Plugin:
    def __init__(self):
        self.name = "{plugin_name}"
        self.license_patterns = [
            b'Trial expired',
            b'Invalid license',
            b'Registration required'
        ]

    def find_license_checks(self, data):
        """Locate license validation routines"""
        findings = []
        for pattern in self.license_patterns:
            if pattern in data:
                findings.append(pattern)
        return findings

    def generate_bypass_strategy(self, binary_path):
        """Generate bypass recommendations"""
        with open(binary_path, 'rb') as f:
            data = f.read()

        license_checks = self.find_license_checks(data)

        strategies = []
        if license_checks:
            strategies.append("NOP out license validation calls")
            strategies.append("Patch return values")

        return strategies

# ... (bypass implementation)'''

        def _generate_preview_network_code(self, plugin_name: str) -> str:
            """Generate preview code for network plugins."""
            return f'''# {plugin_name} - Network Plugin Preview

import socket
import logging

class Plugin:
    def __init__(self):
        self.name = "{plugin_name}"

    def scan_network_strings(self, data):
        """Extract network-related strings"""
        network_indicators = ['http', 'tcp', 'udp', 'socket']
        found = []

        for line in data.split(b'\\x00'):
            line_str = line.decode('ascii', errors='ignore')
            if any(indicator in line_str.lower()
                   for indicator in network_indicators):
                found.append(line_str.strip())

        return found[:20]  # Limit results

    def analyze_communication_patterns(self, binary_path):
        """Analyze potential network communication"""
        with open(binary_path, 'rb') as f:
            data = f.read()

        return {{
            'network_strings': self.scan_network_strings(data),
            'potential_urls': self.extract_urls(data),
            'port_references': self.find_port_numbers(data)
        }}

# ... (network analysis methods)'''

        def _generate_preview_generic_code(self, plugin_name: str) -> str:
            """Generate preview code for generic plugins."""
            return f'''# {plugin_name} - Generic Plugin Preview

import os
import logging

class Plugin:
    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "1.0.0"

    def get_file_info(self, file_path):
        """Get basic file information"""
        stat = os.stat(file_path)
        return {{
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'is_executable': os.access(file_path, os.X_OK)
        }}

    def execute(self, binary_path, *args, **kwargs):
        """Run plugin execution"""
        file_info = self.get_file_info(binary_path)

        return {{
            'status': 'success',
            'message': f'Analysis of {{os.path.basename(binary_path)}} completed',
            'data': file_info
        }}

# Plugin registration
def create_plugin():
    return Plugin()'''

        def browse_plugin_file(self) -> None:
            """Browse for a plugin file to install."""
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Plugin File",
                "",
                "Plugin Files (*.py *.zip);;Python Files (*.py);;ZIP Archives (*.zip);;All Files (*)",
            )

            if file_path:
                self.file_path_edit.setText(file_path)

        def install_from_file(self) -> None:
            """Install plugin from selected file."""
            plugin_file = self.file_path_edit.text().strip()
            if not plugin_file:
                QMessageBox.warning(self, "Warning", "Please select a plugin file first")
                return

            if not os.path.exists(plugin_file):
                QMessageBox.critical(self, "Error", "Selected file does not exist")
                return

            # Start installation thread
            install_dir = os.path.join(self.plugins_dir, os.path.splitext(os.path.basename(plugin_file))[0])
            os.makedirs(install_dir, exist_ok=True)

            self.install_thread = PluginInstallThread(plugin_file, install_dir)
            self.install_thread.progress_updated.connect(self.progress_bar.setValue)
            self.install_thread.status_updated.connect(self.status_label.setText)
            self.install_thread.installation_finished.connect(self.on_installation_finished)

            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.install_thread.start()

        def on_installation_finished(self, success: bool, message: str) -> None:
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

        def create_plugin_template(self) -> None:
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

class {plugin_name.replace(" ", "")}Plugin:
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
        import subprocess
        import os

        findings = []

        try:
            # Check for network-related strings in binary
            if os.path.exists(binary_path):
                with open(binary_path, 'rb') as f:
                    content = f.read()

                # Look for common network indicators
                network_indicators = [b'connect', b'socket', b'recv', b'send', b'WSAStartup',
                                    b'internetopen', b'wininet', b'urlmon']

                for indicator in network_indicators:
                    if indicator in content:
                        findings.append(f"Found network function: {{indicator.decode('ascii', errors='ignore')}}")

        except Exception as e:
            findings.append(f"Analysis error: {{str(e)}}")

        return {{
            'type': 'network_analysis',
            'status': 'completed',
            'findings': findings if findings else ['No network behavior detected']
        }}

    def _scan_vulnerabilities(self, binary_path: str) -> List[Dict[str, Any]]:
        \"\"\"Scan for potential vulnerabilities.\"\"\"
        import os
        vulnerabilities = []

        try:
            if os.path.exists(binary_path):
                with open(binary_path, 'rb') as f:
                    content = f.read()

                # Check for common vulnerability patterns
                vuln_patterns = {{
                    b'strcpy': 'Buffer overflow risk - strcpy function',
                    b'gets': 'Buffer overflow risk - gets function',
                    b'sprintf': 'Format string vulnerability risk',
                    b'system': 'Command injection risk - system call',
                    b'/bin/sh': 'Shell execution detected'
                }}

                for pattern, description in vuln_patterns.items():
                    if pattern in content:
                        vulnerabilities.append({{
                            'type': 'potential_vulnerability',
                            'severity': 'medium',
                            'description': description
                        }})

        except Exception as e:
            vulnerabilities.append({{
                'type': 'scan_error',
                'severity': 'low',
                'description': f'Scan error: {{str(e)}}'
            }})

        return vulnerabilities if vulnerabilities else [{{
            'type': 'scan_complete',
            'severity': 'info',
            'description': 'No obvious vulnerabilities detected'
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
    return {plugin_name.replace(" ", "")}Plugin()

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
    import sys
    import logging

    # Configure logging for testing
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize plugin
    plugin = create_plugin()
    print(f"Plugin: {{plugin.name}} v{{plugin.version}}")
    print(f"Description: {{plugin.description}}")
    print(f"Author: {{plugin.author}}")
    print(f"Category: {{plugin.categories}}")
    print(f"\\nPlugin initialized successfully")

    # Test with command-line argument if provided
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        print(f"\\nTesting with binary: {{binary_path}}")

        # Validate binary
        is_valid, msg = plugin.validate_binary(binary_path)
        print(f"Validation: {{is_valid}} - {{msg}}")

        if is_valid:
            # Execute plugin
            result = plugin.execute(binary_path)
            print(f"Execution status: {{result['status']}}")
            print(f"Message: {{result['message']}}")

            # Display results
            if result.get('data'):
                print(f"\\nResults:")
                for key, value in result['data'].items():
                    if isinstance(value, dict):
                        print(f"  {{key}}:")
                        for k, v in value.items():
                            print(f"    {{k}}: {{v}}")
                    elif isinstance(value, list):
                        print(f"  {{key}}: {{len(value)}} items")
                        for item in value[:5]:
                            print(f"    - {{item}}")
                    else:
                        print(f"  {{key}}: {{value}}")
    else:
        print("\\nUsage: python {{__file__}} <binary_path>")
        print("Provide a binary file path as argument to run analysis")
        sys.exit(1)

    # Cleanup
    plugin.cleanup()
    print("\\nPlugin cleanup completed")
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

        def browse_test_plugin(self) -> None:
            """Browse for a plugin file to test."""
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Plugin to Test",
                self.plugins_dir,
                "Python Files (*.py);;All Files (*)",
            )

            if file_path:
                self.test_file_edit.setText(file_path)

        def test_plugin(self) -> None:
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
                self.test_output.append("OK Syntax check passed")

                # Check for required components
                if "class " in content and "Plugin" in content:
                    self.test_output.append("OK Plugin class found")
                else:
                    self.test_output.append("WARNING Warning: No plugin class found")

                if "def execute(" in content:
                    self.test_output.append("OK Execute method found")
                else:
                    self.test_output.append("WARNING Warning: No execute method found")

                if "PLUGIN_INFO" in content:
                    self.test_output.append("OK Plugin metadata found")
                else:
                    self.test_output.append("WARNING Warning: No plugin metadata found")

                self.test_output.append("\nOK Plugin test completed successfully")

            except SyntaxError as e:
                logger.error("SyntaxError in plugin_manager_dialog: %s", e)
                self.test_output.append(f"ERROR Syntax error: {e}")
            except Exception as e:
                logger.error("Exception in plugin_manager_dialog: %s", e)
                self.test_output.append(f"ERROR Test failed: {e}")

        def refresh_plugins(self) -> None:
            """Refresh installed plugin lists."""
            self.load_installed_plugins()

        def refresh_available_plugins(self) -> None:
            """Refresh the available plugins list - functionality removed."""

        def exec_(self) -> int:
            """Execute dialog."""
            return 0 if not HAS_PYQT else super().exec()
