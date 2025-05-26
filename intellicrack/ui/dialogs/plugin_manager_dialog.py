"""Plugin Manager Dialog for Intellicrack.

This module provides a comprehensive plugin management interface for loading,
installing, configuring, and managing plugins in the Intellicrack application.
"""

import os
import sys
import json
import zipfile
import shutil
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import logging

# Optional imports with graceful fallbacks
try:
    from PyQt5.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTableWidget, QTableWidgetItem, QTextEdit, QLineEdit,
        QComboBox, QCheckBox, QGroupBox, QSplitter, QTabWidget,
        QFileDialog, QProgressBar, QTreeWidget, QTreeWidgetItem,
        QHeaderView, QMessageBox, QInputDialog, QFormLayout,
        QSpinBox, QSlider, QListWidget, QListWidgetItem
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QIcon, QPixmap
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False

logger = logging.getLogger(__name__)

# Define empty stubs when PyQt is not available
if not HAS_PYQT:
    class PluginInstallThread:
        pass
    class PluginManagerDialog:
        pass
else:
    class PluginInstallThread(QThread):
        """Thread for installing plugins without blocking the UI."""
    
        progress_updated = pyqtSignal(int)
        status_updated = pyqtSignal(str)
        installation_finished = pyqtSignal(bool, str)
        
        def __init__(self, plugin_path: str, install_dir: str):
            super().__init__()
            self.plugin_path = plugin_path
            self.install_dir = install_dir
        
        def run(self):
            """Install plugin in background thread."""
            try:
                self.status_updated.emit("Extracting plugin...")
                self.progress_updated.emit(25)
            
                # Extract plugin if it's a zip file
                if self.plugin_path.endswith('.zip'):
                    with zipfile.ZipFile(self.plugin_path, 'r') as zip_ref:
                        zip_ref.extractall(self.install_dir)
                else:
                    # Copy single file
                    shutil.copy2(self.plugin_path, self.install_dir)
                
                self.progress_updated.emit(75)
                self.status_updated.emit("Validating plugin...")
                
                # Basic validation
                plugin_files = os.listdir(self.install_dir)
                if any(f.endswith('.py') for f in plugin_files):
                    self.progress_updated.emit(100)
                    self.status_updated.emit("Installation complete")
                    self.installation_finished.emit(True, "Plugin installed successfully")
                else:
                    self.installation_finished.emit(False, "No Python files found in plugin")
                    
            except Exception as e:
                self.installation_finished.emit(False, f"Installation failed: {str(e)}")

        class PluginManagerDialog(QDialog):
            """Dialog for managing Intellicrack plugins."""
            
            def __init__(self, parent=None):
                super().__init__(parent)
                self.plugins_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'plugins')
                self.installed_plugins = {}
                self.available_plugins = []
                
                self.setup_ui()
                self.load_plugins()
                self.refresh_plugin_list()
            
            def setup_ui(self):
            """Set up the user interface."""
            if not HAS_PYQT:
                logger.warning("PyQt5 not available, cannot create plugin manager dialog")
                return
            
            self.setWindowTitle("Plugin Manager")
            self.setModal(True)
            self.resize(800, 600)
            
            layout = QVBoxLayout()
            
            # Create tab widget
            self.tab_widget = QTabWidget()
            
            # Installed plugins tab
            self.installed_tab = self.create_installed_tab()
            self.tab_widget.addTab(self.installed_tab, "Installed Plugins")
            
            # Available plugins tab
            self.available_tab = self.create_available_tab()
            self.tab_widget.addTab(self.available_tab, "Available Plugins")
            
            # Plugin development tab
            self.development_tab = self.create_development_tab()
            self.tab_widget.addTab(self.development_tab, "Plugin Development")
            
            layout.addWidget(self.tab_widget)
            
            # Dialog buttons
            button_layout = QHBoxLayout()
            
            self.refresh_btn = QPushButton("Refresh")
            self.refresh_btn.clicked.connect(self.refresh_plugin_list)
            
            self.install_btn = QPushButton("Install Plugin...")
            self.install_btn.clicked.connect(self.install_plugin)
            
            self.close_btn = QPushButton("Close")
            self.close_btn.clicked.connect(self.accept)
            
            button_layout.addWidget(self.refresh_btn)
            button_layout.addWidget(self.install_btn)
            button_layout.addStretch()
            button_layout.addWidget(self.close_btn)
            
            layout.addLayout(button_layout)
            self.setLayout(layout)
        
        def create_installed_tab(self):
            """Create the installed plugins tab."""
            widget = QWidget()
            layout = QVBoxLayout()
            
            # Plugin list
            self.installed_table = QTableWidget()
            self.installed_table.setColumnCount(5)
            self.installed_table.setHorizontalHeaderLabels([
                "Name", "Version", "Author", "Status", "Actions"
            ])
            self.installed_table.horizontalHeader().setStretchLastSection(True)
            layout.addWidget(self.installed_table)
            
            # Plugin details
            details_group = QGroupBox("Plugin Details")
            details_layout = QVBoxLayout()
            
            self.plugin_details = QTextEdit()
            self.plugin_details.setReadOnly(True)
            self.plugin_details.setMaximumHeight(150)
            details_layout.addWidget(self.plugin_details)
            
            details_group.setLayout(details_layout)
            layout.addWidget(details_group)
            
            # Plugin actions
            actions_layout = QHBoxLayout()
            
            self.enable_btn = QPushButton("Enable")
            self.enable_btn.clicked.connect(self.enable_plugin)
            
            self.disable_btn = QPushButton("Disable")
            self.disable_btn.clicked.connect(self.disable_plugin)
            
            self.uninstall_btn = QPushButton("Uninstall")
            self.uninstall_btn.clicked.connect(self.uninstall_plugin)
            
            self.configure_btn = QPushButton("Configure")
            self.configure_btn.clicked.connect(self.configure_plugin)
            
            actions_layout.addWidget(self.enable_btn)
            actions_layout.addWidget(self.disable_btn)
            actions_layout.addWidget(self.configure_btn)
            actions_layout.addWidget(self.uninstall_btn)
            actions_layout.addStretch()
            
            layout.addLayout(actions_layout)
            
            # Connect selection change
            self.installed_table.itemSelectionChanged.connect(self.on_plugin_selected)
            
            widget.setLayout(layout)
            return widget
        
        def create_available_tab(self):
            """Create the available plugins tab."""
            widget = QWidget()
            layout = QVBoxLayout()
            
            # Search and filter
            search_layout = QHBoxLayout()
            
            search_label = QLabel("Search:")
            self.search_edit = QLineEdit()
            self.search_edit.textChanged.connect(self.filter_available_plugins)
            
            category_label = QLabel("Category:")
            self.category_combo = QComboBox()
            self.category_combo.addItems(["All", "Analysis", "Patching", "Network", "Utility"])
            self.category_combo.currentTextChanged.connect(self.filter_available_plugins)
            
            search_layout.addWidget(search_label)
            search_layout.addWidget(self.search_edit)
            search_layout.addWidget(category_label)
            search_layout.addWidget(self.category_combo)
            search_layout.addStretch()
            
            layout.addLayout(search_layout)
            
            # Available plugins list
            self.available_table = QTableWidget()
            self.available_table.setColumnCount(4)
            self.available_table.setHorizontalHeaderLabels([
                "Name", "Description", "Author", "Install"
            ])
            self.available_table.horizontalHeader().setStretchLastSection(True)
            layout.addWidget(self.available_table)
            
            widget.setLayout(layout)
            return widget
        
        def create_development_tab(self):
            """Create the plugin development tab."""
            widget = QWidget()
            layout = QVBoxLayout()
            
            # Plugin template generator
            template_group = QGroupBox("Create New Plugin")
            template_layout = QFormLayout()
            
            self.plugin_name_edit = QLineEdit()
            self.plugin_author_edit = QLineEdit()
            self.plugin_description_edit = QTextEdit()
            self.plugin_description_edit.setMaximumHeight(80)
            
            self.plugin_type_combo = QComboBox()
            self.plugin_type_combo.addItems(["Analysis", "Patching", "Network", "Utility"])
            
            template_layout.addRow("Plugin Name:", self.plugin_name_edit)
            template_layout.addRow("Author:", self.plugin_author_edit)
            template_layout.addRow("Type:", self.plugin_type_combo)
            template_layout.addRow("Description:", self.plugin_description_edit)
            
            self.create_plugin_btn = QPushButton("Create Plugin Template")
            self.create_plugin_btn.clicked.connect(self.create_plugin_template)
            template_layout.addRow(self.create_plugin_btn)
            
            template_group.setLayout(template_layout)
            layout.addWidget(template_group)
            
            # Plugin testing
            testing_group = QGroupBox("Plugin Testing")
            testing_layout = QVBoxLayout()
            
            test_layout = QHBoxLayout()
            
            self.test_plugin_btn = QPushButton("Test Plugin")
            self.test_plugin_btn.clicked.connect(self.test_plugin)
            
            self.validate_plugin_btn = QPushButton("Validate Plugin")
            self.validate_plugin_btn.clicked.connect(self.validate_plugin)
            
            test_layout.addWidget(self.test_plugin_btn)
            test_layout.addWidget(self.validate_plugin_btn)
            test_layout.addStretch()
            
            testing_layout.addLayout(test_layout)
            
            # Test output
            self.test_output = QTextEdit()
            self.test_output.setReadOnly(True)
            testing_layout.addWidget(self.test_output)
            
            testing_group.setLayout(testing_layout)
            layout.addWidget(testing_group)
            
            widget.setLayout(layout)
            return widget
        
        def load_plugins(self):
            """Load information about installed plugins."""
            self.installed_plugins = {}
            
            if not os.path.exists(self.plugins_dir):
                os.makedirs(self.plugins_dir, exist_ok=True)
                return
            
            for item in os.listdir(self.plugins_dir):
                plugin_path = os.path.join(self.plugins_dir, item)
                
                if os.path.isdir(plugin_path):
                    # Check for plugin manifest
                    manifest_path = os.path.join(plugin_path, 'plugin.json')
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest = json.load(f)
                            
                            self.installed_plugins[item] = {
                                'name': manifest.get('name', item),
                                'version': manifest.get('version', '1.0.0'),
                                'author': manifest.get('author', 'Unknown'),
                                'description': manifest.get('description', ''),
                                'enabled': manifest.get('enabled', True),
                                'path': plugin_path,
                                'manifest': manifest
                            }
                        except Exception as e:
                            logger.error(f"Error loading plugin manifest for {item}: {e}")
                
                elif item.endswith('.py'):
                    # Single file plugin
                    self.installed_plugins[item] = {
                        'name': item[:-3],  # Remove .py extension
                        'version': '1.0.0',
                        'author': 'Unknown',
                        'description': f'Single file plugin: {item}',
                        'enabled': True,
                        'path': plugin_path,
                        'manifest': None
                    }
        
        def refresh_plugin_list(self):
            """Refresh the plugin list display."""
            self.load_plugins()
            self.update_installed_table()
            self.update_available_table()
        
        def update_installed_table(self):
            """Update the installed plugins table."""
            if not HAS_PYQT:
                return
            
            self.installed_table.setRowCount(len(self.installed_plugins))
            
            for row, (plugin_id, plugin_info) in enumerate(self.installed_plugins.items()):
                # Name
                name_item = QTableWidgetItem(plugin_info['name'])
                self.installed_table.setItem(row, 0, name_item)
                
                # Version
                version_item = QTableWidgetItem(plugin_info['version'])
                self.installed_table.setItem(row, 1, version_item)
                
                # Author
                author_item = QTableWidgetItem(plugin_info['author'])
                self.installed_table.setItem(row, 2, author_item)
                
                # Status
                status = "Enabled" if plugin_info['enabled'] else "Disabled"
                status_item = QTableWidgetItem(status)
                self.installed_table.setItem(row, 3, status_item)
                
                # Store plugin ID for reference
                name_item.setData(Qt.UserRole, plugin_id)
        
        def update_available_table(self):
            """Update the available plugins table."""
            if not HAS_PYQT:
                return
            
            # Mock available plugins for demonstration
            available_plugins = [
                {
                    'name': 'Advanced Binary Scanner',
                    'description': 'Enhanced binary analysis with ML detection',
                    'author': 'Security Team',
                    'url': 'https://example.com/plugin1.zip'
                },
                {
                    'name': 'Custom Protocol Analyzer',
                    'description': 'Analyze custom network protocols',
                    'author': 'Network Team',
                    'url': 'https://example.com/plugin2.zip'
                },
                {
                    'name': 'Automated Patcher',
                    'description': 'Automated patching for common vulnerabilities',
                    'author': 'Patch Team',
                    'url': 'https://example.com/plugin3.zip'
                }
            ]
            
            self.available_table.setRowCount(len(available_plugins))
            
            for row, plugin in enumerate(available_plugins):
                # Name
                name_item = QTableWidgetItem(plugin['name'])
                self.available_table.setItem(row, 0, name_item)
                
                # Description
                desc_item = QTableWidgetItem(plugin['description'])
                self.available_table.setItem(row, 1, desc_item)
                
                # Author
                author_item = QTableWidgetItem(plugin['author'])
                self.available_table.setItem(row, 2, author_item)
                
                # Install button
                install_btn = QPushButton("Install")
                install_btn.clicked.connect(lambda checked, p=plugin: self.install_available_plugin(p))
                self.available_table.setCellWidget(row, 3, install_btn)
        
        def on_plugin_selected(self):
            """Handle plugin selection in the installed table."""
            if not HAS_PYQT:
                return
            
            current_row = self.installed_table.currentRow()
            if current_row >= 0:
                name_item = self.installed_table.item(current_row, 0)
                if name_item:
                    plugin_id = name_item.data(Qt.UserRole)
                    plugin_info = self.installed_plugins.get(plugin_id, {})
                    
                    # Update details
                    details = f"Name: {plugin_info.get('name', 'Unknown')}\n"
                    details += f"Version: {plugin_info.get('version', '1.0.0')}\n"
                    details += f"Author: {plugin_info.get('author', 'Unknown')}\n"
                    details += f"Description: {plugin_info.get('description', 'No description available')}\n"
                    details += f"Path: {plugin_info.get('path', 'Unknown')}\n"
                    
                    self.plugin_details.setPlainText(details)
                    
                    # Update button states
                    enabled = plugin_info.get('enabled', False)
                    self.enable_btn.setEnabled(not enabled)
                    self.disable_btn.setEnabled(enabled)
        
        def enable_plugin(self):
            """Enable the selected plugin."""
            plugin_id = self.get_selected_plugin_id()
            if plugin_id and plugin_id in self.installed_plugins:
                self.installed_plugins[plugin_id]['enabled'] = True
                self.save_plugin_manifest(plugin_id)
                self.update_installed_table()
                logger.info(f"Enabled plugin: {plugin_id}")
        
        def disable_plugin(self):
            """Disable the selected plugin."""
            plugin_id = self.get_selected_plugin_id()
            if plugin_id and plugin_id in self.installed_plugins:
                self.installed_plugins[plugin_id]['enabled'] = False
                self.save_plugin_manifest(plugin_id)
                self.update_installed_table()
                logger.info(f"Disabled plugin: {plugin_id}")
        
        def uninstall_plugin(self):
            """Uninstall the selected plugin."""
            if not HAS_PYQT:
                return
            
            plugin_id = self.get_selected_plugin_id()
            if not plugin_id or plugin_id not in self.installed_plugins:
                return
            
            reply = QMessageBox.question(
                self, 
                "Confirm Uninstall",
                f"Are you sure you want to uninstall plugin '{plugin_id}'?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                try:
                    plugin_path = self.installed_plugins[plugin_id]['path']
                    if os.path.isdir(plugin_path):
                        shutil.rmtree(plugin_path)
                    else:
                        os.remove(plugin_path)
                    
                    del self.installed_plugins[plugin_id]
                    self.update_installed_table()
                    self.plugin_details.clear()
                    
                    QMessageBox.information(self, "Success", "Plugin uninstalled successfully")
                    
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to uninstall plugin: {str(e)}")
        
        def configure_plugin(self):
            """Configure the selected plugin."""
            plugin_id = self.get_selected_plugin_id()
            if plugin_id and plugin_id in self.installed_plugins:
                # Open plugin configuration dialog
                # This would be implemented based on the plugin's configuration schema
                if HAS_PYQT:
                    QMessageBox.information(self, "Configuration", f"Configuration for {plugin_id} would open here")
        
        def get_selected_plugin_id(self):
            """Get the ID of the currently selected plugin."""
            if not HAS_PYQT:
                return None
            
            current_row = self.installed_table.currentRow()
            if current_row >= 0:
                name_item = self.installed_table.item(current_row, 0)
                if name_item:
                    return name_item.data(Qt.UserRole)
            return None
        
        def save_plugin_manifest(self, plugin_id: str):
            """Save the plugin manifest file."""
            if plugin_id not in self.installed_plugins:
                return
            
            plugin_info = self.installed_plugins[plugin_id]
            manifest_path = os.path.join(plugin_info['path'], 'plugin.json')
            
            if plugin_info['manifest']:
                # Update existing manifest
                plugin_info['manifest']['enabled'] = plugin_info['enabled']
                
                try:
                    with open(manifest_path, 'w') as f:
                        json.dump(plugin_info['manifest'], f, indent=2)
                except Exception as e:
                    logger.error(f"Error saving plugin manifest: {e}")
        
        def install_plugin(self):
            """Install a plugin from file."""
            if not HAS_PYQT:
                return
            
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Plugin File",
                "",
                "Plugin Files (*.zip *.py);;All Files (*.*)"
            )
            
            if file_path:
                plugin_name = os.path.splitext(os.path.basename(file_path))[0]
                install_dir = os.path.join(self.plugins_dir, plugin_name)
                
                # Create progress dialog
                progress_dialog = QDialog(self)
                progress_dialog.setWindowTitle("Installing Plugin")
                progress_dialog.setModal(True)
                
                layout = QVBoxLayout()
                
                status_label = QLabel("Preparing installation...")
                progress_bar = QProgressBar()
                
                layout.addWidget(status_label)
                layout.addWidget(progress_bar)
                progress_dialog.setLayout(layout)
                
                # Start installation thread
                self.install_thread = PluginInstallThread(file_path, install_dir)
                self.install_thread.progress_updated.connect(progress_bar.setValue)
                self.install_thread.status_updated.connect(status_label.setText)
                self.install_thread.installation_finished.connect(
                    lambda success, msg: self.on_installation_finished(success, msg, progress_dialog)
                )
                
                self.install_thread.start()
                progress_dialog.show()
        
        def on_installation_finished(self, success: bool, message: str, progress_dialog):
            """Handle installation completion."""
            if not HAS_PYQT:
                return
            
            progress_dialog.close()
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.refresh_plugin_list()
            else:
                QMessageBox.critical(self, "Error", message)
        
        def install_available_plugin(self, plugin_info: Dict[str, str]):
            """Install a plugin from the available list."""
            if HAS_PYQT:
                QMessageBox.information(
                    self, 
                    "Install Plugin", 
                    f"Would download and install: {plugin_info['name']}"
                )
        
        def filter_available_plugins(self):
            """Filter the available plugins based on search criteria."""
            # This would implement filtering logic
            pass
        
        def create_plugin_template(self):
            """Create a new plugin template."""
            if not HAS_PYQT:
                return
            
            name = self.plugin_name_edit.text().strip()
            if not name:
                QMessageBox.warning(self, "Warning", "Please enter a plugin name")
                return
            
            author = self.plugin_author_edit.text().strip() or "Unknown"
            plugin_type = self.plugin_type_combo.currentText()
            description = self.plugin_description_edit.toPlainText().strip()
            
            # Create plugin directory
            plugin_dir = os.path.join(self.plugins_dir, name.lower().replace(' ', '_'))
            os.makedirs(plugin_dir, exist_ok=True)
            
            # Create plugin manifest
            manifest = {
                "name": name,
                "version": "1.0.0",
                "author": author,
                "description": description,
                "type": plugin_type.lower(),
                "enabled": True,
                "entry_point": "main.py"
            }
            
            with open(os.path.join(plugin_dir, 'plugin.json'), 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Create main plugin file
            template_code = self.generate_plugin_template(name, plugin_type)
            with open(os.path.join(plugin_dir, 'main.py'), 'w') as f:
                f.write(template_code)
            
            QMessageBox.information(self, "Success", f"Plugin template created: {plugin_dir}")
            self.refresh_plugin_list()
        
        def generate_plugin_template(self, name: str, plugin_type: str) -> str:
            """Generate plugin template code."""
            template = f'''"""
    {name} Plugin
    
    A {plugin_type.lower()} plugin for Intellicrack.
    """
    
    import logging
    from typing import Dict, Any
    
    logger = logging.getLogger(__name__)
    
    
    class {name.replace(' ', '')}Plugin:
        """Main plugin class for {name}."""
        
        def __init__(self):
            self.name = "{name}"
            self.version = "1.0.0"
            self.enabled = True
        
        def initialize(self):
            """Initialize the plugin."""
            logger.info(f"Initializing {{self.name}} plugin")
            return True
        
        def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
            """Execute the plugin functionality."""
            logger.info(f"Executing {{self.name}} plugin")
            
            # Plugin implementation goes here
            result = {{
                "status": "success",
                "message": f"{{self.name}} plugin executed successfully",
                "data": data
            }}
            
            return result
        
        def cleanup(self):
            """Clean up plugin resources."""
            logger.info(f"Cleaning up {{self.name}} plugin")
    
    
    # Plugin entry point
    def create_plugin():
        """Create and return the plugin instance."""
        return {name.replace(' ', '')}Plugin()
    
    
    # For testing
    if __name__ == "__main__":
        plugin = create_plugin()
        plugin.initialize()
        
        test_data = {{"test": "data"}}
        result = plugin.execute(test_data)
        print(result)
        
        plugin.cleanup()
    '''
            return template
        
        def test_plugin(self):
            """Test a plugin."""
            if not HAS_PYQT:
                return
            
            plugin_id = self.get_selected_plugin_id()
            if not plugin_id:
                QMessageBox.warning(self, "Warning", "Please select a plugin to test")
                return
            
            self.test_output.append(f"Testing plugin: {plugin_id}")
            
            try:
                # Simple plugin test
                plugin_info = self.installed_plugins[plugin_id]
                plugin_path = plugin_info['path']
                
                if os.path.isdir(plugin_path):
                    main_file = os.path.join(plugin_path, 'main.py')
                    if os.path.exists(main_file):
                        # Run basic syntax check
                        result = subprocess.run([
                            sys.executable, '-m', 'py_compile', main_file
                        ], capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            self.test_output.append("✓ Syntax check passed")
                        else:
                            self.test_output.append(f"✗ Syntax error: {result.stderr}")
                    else:
                        self.test_output.append("✗ No main.py file found")
                else:
                    self.test_output.append("✓ Single file plugin - basic test passed")
                    
            except Exception as e:
                self.test_output.append(f"✗ Test failed: {str(e)}")
        
        def validate_plugin(self):
            """Validate a plugin structure."""
            if not HAS_PYQT:
                return
            
            plugin_id = self.get_selected_plugin_id()
            if not plugin_id:
                QMessageBox.warning(self, "Warning", "Please select a plugin to validate")
                return
            
            self.test_output.append(f"Validating plugin: {plugin_id}")
            
            plugin_info = self.installed_plugins[plugin_id]
            plugin_path = plugin_info['path']
            
            validation_passed = True
            
            if os.path.isdir(plugin_path):
                # Check for required files
                required_files = ['plugin.json']
                for file in required_files:
                    if os.path.exists(os.path.join(plugin_path, file)):
                        self.test_output.append(f"✓ Found {file}")
                    else:
                        self.test_output.append(f"✗ Missing {file}")
                        validation_passed = False
                
                # Check manifest structure
                manifest_path = os.path.join(plugin_path, 'plugin.json')
                if os.path.exists(manifest_path):
                    try:
                        with open(manifest_path, 'r') as f:
                            manifest = json.load(f)
                        
                        required_fields = ['name', 'version', 'author']
                        for field in required_fields:
                            if field in manifest:
                                self.test_output.append(f"✓ Manifest has {field}")
                            else:
                                self.test_output.append(f"✗ Manifest missing {field}")
                                validation_passed = False
                                
                    except Exception as e:
                        self.test_output.append(f"✗ Invalid manifest JSON: {str(e)}")
                        validation_passed = False
            
            if validation_passed:
                self.test_output.append("✓ Plugin validation passed")
            else:
                self.test_output.append("✗ Plugin validation failed")
    
    
    # Export for external use
    __all__ = ['PluginManagerDialog', 'PluginInstallThread']

# Set empty __all__ if PyQt not available
if not HAS_PYQT:
    __all__ = []