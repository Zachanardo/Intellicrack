"""Frida GUI Integration for Script Management.

Production-ready GUI components for Frida script integration including
parameter configuration, real-time output, visualization, and debugging.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import time
from datetime import datetime
from pathlib import Path
from threading import Thread

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.analysis.frida_script_manager import FridaScriptConfig, FridaScriptManager, ScriptCategory


class FridaScriptParameterWidget(QDialog):
    """Advanced parameter configuration dialog for Frida scripts."""

    def __init__(self, script_config: FridaScriptConfig, parent: QWidget | None = None) -> None:
        """Initialize the FridaScriptParameterWidget with a script configuration.

        Args:
            script_config: Configuration for the Frida script to configure.
            parent: Parent widget for this dialog. Defaults to None.

        """
        super().__init__(parent)
        self.script_config = script_config
        self.parameter_widgets = {}
        self.custom_values = {}
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the parameter configuration UI."""
        self.setWindowTitle(f"Configure: {self.script_config.name}")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        layout = QVBoxLayout()

        # Script information
        info_group = QGroupBox("Script Information")
        info_layout = QFormLayout()
        info_layout.addRow("Name:", QLabel(self.script_config.name))
        info_layout.addRow("Category:", QLabel(self.script_config.category.value))
        info_layout.addRow("Description:", QLabel(self.script_config.description))

        # Add requirements indicators
        req_layout = QHBoxLayout()
        if self.script_config.requires_admin:
            admin_label = QLabel("WARNING️ Requires Admin")
            admin_label.setStyleSheet("color: orange;")
            req_layout.addWidget(admin_label)
        if self.script_config.supports_spawn:
            spawn_label = QLabel("OK Spawn Mode")
            spawn_label.setStyleSheet("color: green;")
            req_layout.addWidget(spawn_label)
        if self.script_config.supports_attach:
            attach_label = QLabel("OK Attach Mode")
            attach_label.setStyleSheet("color: green;")
            req_layout.addWidget(attach_label)
        if req_layout.count() > 0:
            info_layout.addRow("Capabilities:", req_layout)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Parameters configuration
        if self.script_config.parameters:
            param_group = QGroupBox("Parameters")
            param_layout = QFormLayout()

            for param_name, default_value in self.script_config.parameters.items():
                widget = self._create_parameter_widget(param_name, default_value)
                self.parameter_widgets[param_name] = widget

                # Add description label
                desc_label = QLabel(param_name.replace("_", " ").title())
                desc_label.setToolTip(f"Parameter: {param_name}")

                param_layout.addRow(desc_label, widget)

            param_group.setLayout(param_layout)
            layout.addWidget(param_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QFormLayout()

        # Timeout setting
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setValue(60)
        self.timeout_spin.setSuffix(" seconds")
        advanced_layout.addRow("Timeout:", self.timeout_spin)

        # Output format
        self.output_combo = QComboBox()
        self.output_combo.addItems(["JSON", "Text", "Binary", "XML"])
        advanced_layout.addRow("Output Format:", self.output_combo)

        # Logging level
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["Debug", "Info", "Warning", "Error"])
        self.log_level_combo.setCurrentText("Info")
        advanced_layout.addRow("Log Level:", self.log_level_combo)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        # Buttons
        button_layout = QHBoxLayout()

        self.test_button = QPushButton("Test Parameters")
        self.test_button.clicked.connect(self.test_parameters)

        self.save_preset_button = QPushButton("Save Preset")
        self.save_preset_button.clicked.connect(self.save_preset)

        self.load_preset_button = QPushButton("Load Preset")
        self.load_preset_button.clicked.connect(self.load_preset)

        self.run_button = QPushButton("Run Script")
        self.run_button.clicked.connect(self.accept)
        self.run_button.setDefault(True)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.save_preset_button)
        button_layout.addWidget(self.load_preset_button)
        button_layout.addStretch()
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def _create_parameter_widget(self, name: str, default_value: object) -> QWidget:
        """Create appropriate widget based on parameter type."""
        if isinstance(default_value, bool):
            widget = QCheckBox()
            widget.setChecked(default_value)

        elif isinstance(default_value, int):
            widget = QSpinBox()
            widget.setRange(-999999, 999999)
            widget.setValue(default_value)

        elif isinstance(default_value, float):
            widget = QDoubleSpinBox()
            widget.setRange(-999999.0, 999999.0)
            widget.setValue(default_value)
            widget.setDecimals(4)

        elif isinstance(default_value, list):
            widget = QTextEdit()
            widget.setPlainText(json.dumps(default_value, indent=2))
            widget.setMaximumHeight(100)

        elif isinstance(default_value, dict):
            widget = QTextEdit()
            widget.setPlainText(json.dumps(default_value, indent=2))
            widget.setMaximumHeight(150)

        elif default_value is None:
            # Special handling for None values
            widget = QLineEdit()
            widget.setToolTip("Optional parameter - leave empty for None")
            widget.setStyleSheet("QLineEdit { color: gray; }")
            widget.setText("")

        else:  # String or other
            widget = QLineEdit()
            widget.setText(str(default_value))

            # Add validation for specific parameter types
            if "mac" in name.lower():
                widget.setToolTip("MAC Address format: XX:XX:XX:XX:XX:XX")
                if not widget.text():
                    widget.setText("00:00:00:00:00:00")
            elif "ip" in name.lower():
                widget.setToolTip("IP Address format: X.X.X.X")
                if not widget.text():
                    widget.setText("127.0.0.1")
            elif "port" in name.lower():
                widget = QSpinBox()
                widget.setRange(1, 65535)
                widget.setValue(int(default_value) if default_value else 80)

        return widget

    def get_parameters(self) -> dict[str, object]:
        """Get configured parameter values."""
        parameters = {}

        for param_name, widget in self.parameter_widgets.items():
            if isinstance(widget, QCheckBox):
                parameters[param_name] = widget.isChecked()

            elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                parameters[param_name] = widget.value()

            elif isinstance(widget, QTextEdit):
                try:
                    parameters[param_name] = json.loads(widget.toPlainText())
                except json.JSONDecodeError:
                    # Fallback to list of lines
                    parameters[param_name] = widget.toPlainText().split("\n")

            elif isinstance(widget, QLineEdit):
                text = widget.text()
                if text in {"", "None"}:
                    parameters[param_name] = None
                else:
                    parameters[param_name] = text

        # Add advanced options
        parameters["timeout"] = self.timeout_spin.value()
        parameters["output_format"] = self.output_combo.currentText().lower()
        parameters["log_level"] = self.log_level_combo.currentText().lower()

        return parameters

    def test_parameters(self) -> None:
        """Test parameter validation."""
        try:
            params = self.get_parameters()
            QMessageBox.information(
                self, "Parameters Valid", f"Parameters validated successfully:\n{json.dumps(params, indent=2)[:500]}...",
            )
        except Exception as e:
            QMessageBox.warning(self, "Validation Error", f"Parameter validation failed: {e}")

    def save_preset(self) -> None:
        """Save current parameters as preset."""
        params = self.get_parameters()
        preset_name, ok = QInputDialog.getText(self, "Save Preset", "Enter preset name:")

        if ok and preset_name:
            preset_file = Path.home() / ".intellicrack" / "frida_presets" / f"{preset_name}.json"
            preset_file.parent.mkdir(parents=True, exist_ok=True)

            with open(preset_file, "w") as f:
                json.dump(params, f, indent=2)

            QMessageBox.information(self, "Success", f"Preset saved: {preset_name}")

    def load_preset(self) -> None:
        """Load parameters from preset."""
        preset_dir = Path.home() / ".intellicrack" / "frida_presets"
        preset_dir.mkdir(parents=True, exist_ok=True)

        file_path, _ = QFileDialog.getOpenFileName(self, "Load Preset", str(preset_dir), "JSON Files (*.json)")

        if file_path:
            with open(file_path) as f:
                params = json.load(f)

            # Set parameters in widgets
            for param_name, value in params.items():
                if param_name in self.parameter_widgets:
                    widget = self.parameter_widgets[param_name]

                    if isinstance(widget, QCheckBox):
                        widget.setChecked(bool(value))
                    elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                        widget.setValue(value)
                    elif isinstance(widget, QTextEdit):
                        widget.setPlainText(json.dumps(value, indent=2))
                    elif isinstance(widget, QLineEdit):
                        widget.setText(str(value) if value is not None else "")


class FridaScriptOutputWidget(QWidget):
    """Real-time output viewer for Frida scripts."""

    def __init__(self) -> None:
        """Initialize the FridaScriptOutputWidget for real-time script output."""
        super().__init__()
        self.script_outputs = {}
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize output viewer UI."""
        layout = QVBoxLayout()

        # Tab widget for multiple scripts
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)

        layout.addWidget(self.tab_widget)
        self.setLayout(layout)

    def add_script_output(self, script_name: str, session_id: str) -> None:
        """Add new output tab for script."""
        tab = ScriptOutputTab(script_name, session_id)
        self.tab_widget.addTab(tab, script_name)
        self.script_outputs[session_id] = tab

        # Switch to new tab
        self.tab_widget.setCurrentWidget(tab)

    def update_output(self, session_id: str, message: object) -> None:
        """Update script output."""
        if session_id in self.script_outputs:
            self.script_outputs[session_id].add_message(message)

    def close_tab(self, index: int) -> None:
        """Close output tab."""
        widget = self.tab_widget.widget(index)
        if widget:
            session_id = widget.session_id
            if session_id in self.script_outputs:
                del self.script_outputs[session_id]
        self.tab_widget.removeTab(index)


class ScriptOutputTab(QWidget):
    """Individual output tab for a script."""

    def __init__(self, script_name: str, session_id: str) -> None:
        """Initialize the ScriptOutputTab for a specific script.

        Args:
            script_name: Name of the script this tab represents.
            session_id: Unique identifier for the script session.

        """
        super().__init__()
        self.script_name = script_name
        self.session_id = session_id
        self.messages = []
        self.data = {}
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize tab UI."""
        layout = QVBoxLayout()

        # Toolbar
        toolbar_layout = QHBoxLayout()

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_output)

        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_output)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Info", "Warning", "Error", "Data"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)

        toolbar_layout.addWidget(QLabel("Filter:"))
        toolbar_layout.addWidget(self.filter_combo)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.clear_button)
        toolbar_layout.addWidget(self.export_button)

        layout.addLayout(toolbar_layout)

        # Splitter for output and data
        splitter = QSplitter()

        # Message output
        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 9))
        self.output_text.setMaximumBlockCount(10000)  # Limit history
        splitter.addWidget(self.output_text)

        # Data tree
        self.data_tree = QTreeWidget()
        self.data_tree.setHeaderLabels(["Key", "Value", "Type"])
        splitter.addWidget(self.data_tree)

        splitter.setSizes([700, 300])
        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Status: Running")
        layout.addWidget(self.status_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

    def add_message(self, message: object) -> None:
        """Add message to output."""
        self.messages.append(message)

        # Format message
        formatted = self.format_message(message)

        # Add to output with color coding
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Apply color based on message type
        color = self.get_message_color(message)
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))

        cursor.insertText(formatted + "\n", text_format)

        # Auto-scroll to bottom
        self.output_text.verticalScrollBar().setValue(self.output_text.verticalScrollBar().maximum())

        # Update data tree if message contains data
        if isinstance(message, dict) and "data" in message:
            self.update_data_tree(message["data"])

    def format_message(self, message: object) -> str:
        """Format message for display."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if isinstance(message, dict):
            msg_type = message.get("type", "info").upper()
            content = message.get("payload", message)

            if isinstance(content, dict):
                content = json.dumps(content, indent=2)

            return f"[{timestamp}] [{msg_type}] {content}"
        return f"[{timestamp}] {message}"

    def get_message_color(self, message: object) -> str:
        """Get color for message based on type."""
        if isinstance(message, dict):
            msg_type = message.get("type", "").lower()

            if msg_type == "error" or "error" in str(message).lower():
                return "#ff6b6b"  # Red
            if msg_type == "warning" or "warn" in str(message).lower():
                return "#ffa726"  # Orange
            if msg_type == "success" or "hook_installed" in str(message):
                return "#66bb6a"  # Green
            if msg_type == "data":
                return "#42a5f5"  # Blue

        return "#e0e0e0"  # Default gray

    def update_data_tree(self, data: dict[str, object]) -> None:
        """Update data tree with collected data."""
        self.data.update(data)

        # Clear and rebuild tree
        self.data_tree.clear()
        self._add_dict_to_tree(self.data, self.data_tree.invisibleRootItem())

    def _add_dict_to_tree(self, data: object, parent: QTreeWidgetItem, key: str = "") -> None:
        """Recursively add dictionary to tree."""
        if isinstance(data, dict):
            for k, v in data.items():
                item = QTreeWidgetItem(parent)
                item.setText(0, str(k))

                if isinstance(v, (dict, list)):
                    item.setText(1, f"[{type(v).__name__}]")
                    item.setText(2, type(v).__name__)
                    self._add_dict_to_tree(v, item)
                else:
                    item.setText(1, str(v))
                    item.setText(2, type(v).__name__)

        elif isinstance(data, list):
            for i, v in enumerate(data):
                item = QTreeWidgetItem(parent)
                item.setText(0, f"[{i}]")

                if isinstance(v, (dict, list)):
                    item.setText(1, f"[{type(v).__name__}]")
                    item.setText(2, type(v).__name__)
                    self._add_dict_to_tree(v, item)
                else:
                    item.setText(1, str(v))
                    item.setText(2, type(v).__name__)

    def apply_filter(self, filter_type: str) -> None:
        """Apply message filter."""
        # This would filter displayed messages

    def clear_output(self) -> None:
        """Clear output display."""
        self.output_text.clear()
        self.messages.clear()

    def export_output(self) -> None:
        """Export output to file."""
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Output", f"{self.script_name}_output.json", "JSON Files (*.json)")

        if file_path:
            export_data = {"script_name": self.script_name, "session_id": self.session_id, "messages": self.messages, "data": self.data}

            with open(file_path, "w") as f:
                json.dump(export_data, f, indent=2)

            QMessageBox.information(self, "Success", f"Output exported to {file_path}")


class FridaScriptDebuggerWidget(QWidget):
    """Debugging interface for Frida scripts."""

    def __init__(self) -> None:
        """Initialize the FridaScriptDebuggerWidget for debugging Frida scripts."""
        super().__init__()
        self.breakpoints = {}
        self.watch_expressions = []
        self.call_stack = []
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize debugger UI."""
        layout = QVBoxLayout()

        # Toolbar
        toolbar = QToolBar()

        self.continue_action = toolbar.addAction("▶ Continue")
        self.pause_action = toolbar.addAction("⏸ Pause")
        self.step_over_action = toolbar.addAction("↷ Step Over")
        self.step_into_action = toolbar.addAction("↓ Step Into")
        self.step_out_action = toolbar.addAction("↑ Step Out")
        self.restart_action = toolbar.addAction("🔄 Restart")

        layout.addWidget(toolbar)

        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Code view
        code_widget = QWidget()
        code_layout = QVBoxLayout()

        self.code_editor = QPlainTextEdit()
        self.code_editor.setFont(QFont("Consolas", 10))
        self.code_editor.setReadOnly(True)

        code_layout.addWidget(QLabel("Script Code"))
        code_layout.addWidget(self.code_editor)
        code_widget.setLayout(code_layout)

        main_splitter.addWidget(code_widget)

        # Debug panels
        debug_tabs = QTabWidget()

        # Breakpoints
        self.breakpoints_widget = QTableWidget()
        self.breakpoints_widget.setColumnCount(4)
        self.breakpoints_widget.setHorizontalHeaderLabels(["Line", "Function", "Condition", "Hit Count"])
        debug_tabs.addTab(self.breakpoints_widget, "Breakpoints")

        # Watch expressions
        self.watch_widget = QTableWidget()
        self.watch_widget.setColumnCount(3)
        self.watch_widget.setHorizontalHeaderLabels(["Expression", "Value", "Type"])
        debug_tabs.addTab(self.watch_widget, "Watch")

        # Call stack
        self.callstack_widget = QListWidget()
        debug_tabs.addTab(self.callstack_widget, "Call Stack")

        # Console
        self.console_widget = QPlainTextEdit()
        self.console_widget.setFont(QFont("Consolas", 9))
        debug_tabs.addTab(self.console_widget, "Console")

        main_splitter.addWidget(debug_tabs)
        main_splitter.setSizes([600, 400])

        layout.addWidget(main_splitter)
        self.setLayout(layout)

    def load_script(self, script_path: str) -> None:
        """Load script for debugging."""
        with open(script_path, encoding="utf-8") as f:
            content = f.read()

        # Add line numbers
        lines = content.split("\n")
        numbered = []
        for i, line in enumerate(lines, 1):
            numbered.append(f"{i:4d} | {line}")

        self.code_editor.setPlainText("\n".join(numbered))

    def add_breakpoint(self, line: int, condition: str = "") -> None:
        """Add breakpoint."""
        row = self.breakpoints_widget.rowCount()
        self.breakpoints_widget.insertRow(row)

        self.breakpoints_widget.setItem(row, 0, QTableWidgetItem(str(line)))
        self.breakpoints_widget.setItem(row, 1, QTableWidgetItem(""))
        self.breakpoints_widget.setItem(row, 2, QTableWidgetItem(condition))
        self.breakpoints_widget.setItem(row, 3, QTableWidgetItem("0"))

        self.breakpoints[line] = {"condition": condition, "hits": 0}

    def update_callstack(self, stack: list[str]) -> None:
        """Update call stack display."""
        self.callstack_widget.clear()
        self.callstack_widget.addItems(stack)

    def log_console(self, message: str) -> None:
        """Log message to console."""
        self.console_widget.appendPlainText(message)


class FridaScriptCreatorWidget(QDialog):
    """Wizard for creating custom Frida scripts."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the FridaScriptCreatorWidget with an optional parent."""
        super().__init__(parent)
        self.setWindowTitle("Create Custom Frida Script")
        self.setMinimumSize(900, 700)
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize creator UI."""
        layout = QVBoxLayout()

        # Tab widget
        self.tab_widget = QTabWidget()

        # Basic info tab
        self.info_tab = self.create_info_tab()
        self.tab_widget.addTab(self.info_tab, "Basic Information")

        # Hooks configuration tab
        self.hooks_tab = self.create_hooks_tab()
        self.tab_widget.addTab(self.hooks_tab, "Hooks Configuration")

        # Code editor tab
        self.code_tab = self.create_code_tab()
        self.tab_widget.addTab(self.code_tab, "Script Code")

        # Templates tab
        self.templates_tab = self.create_templates_tab()
        self.tab_widget.addTab(self.templates_tab, "Templates")

        layout.addWidget(self.tab_widget)

        # Buttons
        button_layout = QHBoxLayout()

        self.validate_button = QPushButton("Validate")
        self.validate_button.clicked.connect(self.validate_script)

        self.test_button = QPushButton("Test")
        self.test_button.clicked.connect(self.test_script)

        self.save_button = QPushButton("Save Script")
        self.save_button.clicked.connect(self.save_script)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.reject)

        button_layout.addWidget(self.validate_button)
        button_layout.addWidget(self.test_button)
        button_layout.addStretch()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.close_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def create_info_tab(self) -> QWidget:
        """Create basic information tab."""
        tab = QWidget()
        layout = QFormLayout()

        self.name_edit = QLineEdit()
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)

        self.category_combo = QComboBox()
        for category in ScriptCategory:
            self.category_combo.addItem(category.value)

        self.admin_check = QCheckBox("Requires Administrator")
        self.spawn_check = QCheckBox("Supports Spawn Mode")
        self.spawn_check.setChecked(True)
        self.attach_check = QCheckBox("Supports Attach Mode")
        self.attach_check.setChecked(True)

        layout.addRow("Script Name:", self.name_edit)
        layout.addRow("Description:", self.description_edit)
        layout.addRow("Category:", self.category_combo)
        layout.addRow("Requirements:", self.admin_check)
        layout.addRow("", self.spawn_check)
        layout.addRow("", self.attach_check)

        tab.setLayout(layout)
        return tab

    def create_hooks_tab(self) -> QWidget:
        """Create hooks configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout()

        # Hook builder
        builder_group = QGroupBox("Hook Builder")
        builder_layout = QFormLayout()

        self.module_edit = QLineEdit()
        self.module_edit.setToolTip("Module name (e.g., kernel32.dll)")
        self.function_edit = QLineEdit()
        self.function_edit.setToolTip("Function name (e.g., CreateFileW)")

        self.hook_type_combo = QComboBox()
        self.hook_type_combo.addItems(["onEnter", "onLeave", "replace"])

        builder_layout.addRow("Module:", self.module_edit)
        builder_layout.addRow("Function:", self.function_edit)
        builder_layout.addRow("Hook Type:", self.hook_type_combo)

        add_hook_button = QPushButton("Add Hook")
        add_hook_button.clicked.connect(self.add_hook)
        builder_layout.addRow("", add_hook_button)

        builder_group.setLayout(builder_layout)
        layout.addWidget(builder_group)

        # Hooks list
        self.hooks_list = QListWidget()
        layout.addWidget(QLabel("Configured Hooks:"))
        layout.addWidget(self.hooks_list)

        tab.setLayout(layout)
        return tab

    def create_code_tab(self) -> QWidget:
        """Create code editor tab."""
        tab = QWidget()
        layout = QVBoxLayout()

        # Code editor
        self.code_editor = QPlainTextEdit()
        self.code_editor.setFont(QFont("Consolas", 10))
        self.code_editor.setPlainText(self.get_default_template())

        layout.addWidget(self.code_editor)

        tab.setLayout(layout)
        return tab

    def create_templates_tab(self) -> QWidget:
        """Create templates tab."""
        tab = QWidget()
        layout = QVBoxLayout()

        # Template list
        self.template_list = QListWidget()
        templates = [
            "Basic Hook",
            "License Bypass",
            "Anti-Debug Bypass",
            "Memory Scanner",
            "API Monitor",
            "Network Interceptor",
            "Crypto Detector",
            "String Decryptor",
            "Unpacker",
        ]
        self.template_list.addItems(templates)
        self.template_list.itemDoubleClicked.connect(self.load_template)

        layout.addWidget(QLabel("Available Templates:"))
        layout.addWidget(self.template_list)

        load_button = QPushButton("Load Selected Template")
        load_button.clicked.connect(lambda: self.load_template(self.template_list.currentItem()))
        layout.addWidget(load_button)

        tab.setLayout(layout)
        return tab

    def get_default_template(self) -> str:
        """Get default script template."""
        return """// Frida Script - Created with Intellicrack
// @description: Custom Frida script
// @author: Intellicrack
// @version: 1.0.0

// Configuration
const CONFIG = {
    verbose: true,
    collectData: true
};

// Main function
function main() {
    console.log('[*] Script loaded');

    // Add your hooks here

    send({ type: 'info', payload: 'Script initialized' });
}

// Execute
if (typeof ObjC !== 'undefined') {
    // iOS
    main();
} else if (Java.available) {
    // Android
    Java.perform(main);
} else {
    // Native
    main();
}
"""

    def add_hook(self) -> None:
        """Add hook to list."""
        module = self.module_edit.text()
        function = self.function_edit.text()
        hook_type = self.hook_type_combo.currentText()

        if module and function:
            hook_str = f"{module}!{function} ({hook_type})"
            self.hooks_list.addItem(hook_str)

            # Clear inputs
            self.module_edit.clear()
            self.function_edit.clear()

    def load_template(self, item: QListWidget | None) -> None:
        """Load selected template."""
        if not item:
            return

        template_name = item.text()
        template_code = self.get_template_code(template_name)
        self.code_editor.setPlainText(template_code)

        # Switch to code tab
        self.tab_widget.setCurrentIndex(2)

    def get_template_code(self, template_name: str) -> str:
        """Get template code by name."""
        templates = {
            "License Bypass": self.get_license_bypass_template(),
            "Anti-Debug Bypass": self.get_antidebug_template(),
            "Memory Scanner": self.get_memory_scanner_template(),
        }
        return templates.get(template_name, self.get_default_template())

    def get_license_bypass_template(self) -> str:
        """Get license bypass template."""
        return """// License Validation Bypass
// Hooks and bypasses common license validation functions

const targetFunctions = [
    'IsLicenseValid', 'CheckLicense', 'ValidateLicense',
    'VerifyRegistration', 'CheckActivation', 'IsRegistered'
];

// Hook all validation functions
targetFunctions.forEach(funcName => {
    const addr = Module.findExportByName(null, funcName);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                send({
                    type: 'license_check',
                    payload: { function: funcName, args: args }
                });
            },
            onLeave: function(retval) {
                send({
                    type: 'license_result',
                    payload: {
                        function: funcName,
                        original: retval.toInt32(),
                        modified: 1
                    }
                });
                retval.replace(1); // Force success
            }
        });
        send({ type: 'hook_installed', payload: { function: funcName }});
    }
});

// Hook registry checks
const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
if (RegQueryValueExW) {
    Interceptor.attach(RegQueryValueExW, {
        onEnter: function(args) {
            const keyName = args[1].readUtf16String();
            if (keyName && keyName.includes('License')) {
                this.isLicenseQuery = true;
                send({
                    type: 'registry_query',
                    payload: { key: keyName }
                });
            }
        },
        onLeave: function(retval) {
            if (this.isLicenseQuery) {
                retval.replace(0); // Success
            }
        }
    });
}

send({ type: 'ready', payload: 'License bypass hooks installed' });
"""

    def get_antidebug_template(self) -> str:
        """Get anti-debug bypass template."""
        return """// Anti-Debug Bypass
// Bypasses common anti-debugging techniques

// IsDebuggerPresent
const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (IsDebuggerPresent) {
    Interceptor.attach(IsDebuggerPresent, {
        onLeave: function(retval) {
            retval.replace(0); // No debugger
            send({ type: 'antidebug', payload: 'IsDebuggerPresent bypassed' });
        }
    });
}

// CheckRemoteDebuggerPresent
const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (CheckRemoteDebuggerPresent) {
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onEnter: function(args) {
            this.pDebuggerPresent = args[1];
        },
        onLeave: function(retval) {
            if (this.pDebuggerPresent) {
                Memory.writeU8(this.pDebuggerPresent, 0);
                send({ type: 'antidebug', payload: 'CheckRemoteDebuggerPresent bypassed' });
            }
        }
    });
}

// NtQueryInformationProcess
const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
if (NtQueryInformationProcess) {
    Interceptor.attach(NtQueryInformationProcess, {
        onEnter: function(args) {
            this.infoClass = args[1].toInt32();
            this.buffer = args[2];
        },
        onLeave: function(retval) {
            if (this.infoClass === 7) { // ProcessDebugPort
                Memory.writeU32(this.buffer, 0);
                send({ type: 'antidebug', payload: 'ProcessDebugPort check bypassed' });
            }
        }
    });
}

// PEB BeingDebugged flag
const peb = Process.enumerateModules()[0].base;
const beingDebuggedOffset = Process.pointerSize === 8 ? 0x2 : 0x2;
Memory.writeU8(peb.add(beingDebuggedOffset), 0);

send({ type: 'ready', payload: 'Anti-debug bypasses installed' });
"""

    def get_memory_scanner_template(self) -> str:
        """Get memory scanner template."""
        return """// Memory Scanner
// Scans memory for patterns and values

function scanMemory(pattern, maxResults = 10) {
    const results = [];
    const ranges = Process.enumerateRanges('r--');

    for (const range of ranges) {
        if (results.length >= maxResults) break;

        try {
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    const context = {
                        address: address.toString(),
                        size: size,
                        data: Memory.readByteArray(address, Math.min(size, 128))
                    };

                    results.push(context);

                    send({
                        type: 'pattern_found',
                        payload: context
                    });

                    return results.length < maxResults;
                }
            });
        } catch (e) {
            // Skip inaccessible regions
        }
    }

    return results;
}

// Scan for common license patterns
const patterns = [
    '6C 69 63 65 6E 73 65', // "license"
    '73 65 72 69 61 6C', // "serial"
    '6B 65 79', // "key"
    '72 65 67 69 73 74', // "regist"
];

patterns.forEach(pattern => {
    const results = scanMemory(pattern, 5);
    send({
        type: 'scan_complete',
        payload: {
            pattern: pattern,
            found: results.length
        }
    });
});

send({ type: 'ready', payload: 'Memory scanner initialized' });
"""

    def validate_script(self) -> None:
        """Validate script syntax."""
        script_code = self.code_editor.toPlainText()

        # Basic validation
        if not script_code.strip():
            QMessageBox.warning(self, "Validation Error", "Script is empty")
            return

        # Check for common issues
        issues = []

        if "Interceptor.attach" not in script_code and "Java.perform" not in script_code:
            issues.append("No hooks detected")

        if "send(" not in script_code:
            issues.append("No message sending detected")

        if issues:
            QMessageBox.warning(self, "Validation Warnings", "\n".join(issues))
        else:
            QMessageBox.information(self, "Validation Success", "Script appears valid")

    def test_script(self) -> None:
        """Test script (would need actual Frida connection)."""
        QMessageBox.information(self, "Test", "Script testing requires active Frida connection")

    def save_script(self) -> None:
        """Save script to file."""
        name = self.name_edit.text()
        if not name:
            QMessageBox.warning(self, "Error", "Please enter a script name")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Script", f"{name}.js", "JavaScript Files (*.js)")

        if file_path:
            # Add metadata header
            metadata = {
                "name": name,
                "description": self.description_edit.toPlainText(),
                "category": self.category_combo.currentText(),
                "requires_admin": self.admin_check.isChecked(),
                "supports_spawn": self.spawn_check.isChecked(),
                "supports_attach": self.attach_check.isChecked(),
            }

            header = f"""/**
 * @metadata
 * {json.dumps(metadata, indent=2)}
 * @end
 */

"""

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(header)
                f.write(self.code_editor.toPlainText())

            QMessageBox.information(self, "Success", f"Script saved to {file_path}")
            self.accept()


def integrate_frida_gui(main_app: object) -> bool:
    """Integrate Frida GUI components."""
    # Create Frida menu if not exists
    if not hasattr(main_app, "frida_menu"):
        main_app.frida_menu = main_app.menuBar().addMenu("Frida")

    # Add actions
    configure_action = QAction("Configure Script", main_app)
    configure_action.triggered.connect(lambda: show_parameter_dialog(main_app))
    main_app.frida_menu.addAction(configure_action)

    output_action = QAction("Show Output Viewer", main_app)
    output_action.triggered.connect(lambda: show_output_viewer(main_app))
    main_app.frida_menu.addAction(output_action)

    debug_action = QAction("Script Debugger", main_app)
    debug_action.triggered.connect(lambda: show_debugger(main_app))
    main_app.frida_menu.addAction(debug_action)

    create_action = QAction("Create Script", main_app)
    create_action.triggered.connect(lambda: show_creator(main_app))
    main_app.frida_menu.addAction(create_action)

    # Create output viewer widget
    if not hasattr(main_app, "frida_output_widget"):
        main_app.frida_output_widget = FridaScriptOutputWidget()

    return True


def show_parameter_dialog(main_app: object) -> None:
    """Show parameter configuration dialog."""
    # Get script manager
    if not hasattr(main_app, "frida_script_manager"):
        scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "frida"
        main_app.frida_script_manager = FridaScriptManager(scripts_dir)

    manager = main_app.frida_script_manager

    # Get list of available scripts
    script_names = list(manager.scripts.keys())
    if not script_names:
        QMessageBox.warning(main_app, "No Scripts", "No Frida scripts found")
        return

    # Select script
    script_name, ok = QInputDialog.getItem(main_app, "Select Script", "Choose a script to configure:", script_names, 0, False)

    if ok and script_name:
        config = manager.get_script_config(script_name)
        if config:
            dialog = FridaScriptParameterWidget(config, main_app)
            if dialog.exec():
                params = dialog.get_parameters()

                # Get target
                target, ok = QInputDialog.getText(main_app, "Target Process", "Enter target process (path for spawn, PID/name for attach):")

                if ok and target:
                    # Create output tab
                    if hasattr(main_app, "frida_output_widget"):
                        session_id = f"{script_name}_{target}_{time.time()}"
                        main_app.frida_output_widget.add_script_output(script_name, session_id)

                        # Execute script in background
                        def output_callback(message: object) -> None:
                            main_app.frida_output_widget.update_output(session_id, message)

                        # Run in thread
                        thread = Thread(target=manager.execute_script, args=(script_name, target, "spawn", params, output_callback))
                        thread.daemon = True
                        thread.start()


def show_output_viewer(main_app: object) -> None:
    """Show output viewer window."""
    if hasattr(main_app, "frida_output_widget"):
        main_app.frida_output_widget.show()


def show_debugger(main_app: object) -> None:
    """Show debugger window."""
    debugger = FridaScriptDebuggerWidget()
    debugger.show()


def show_creator(main_app: object) -> None:
    """Show script creator dialog."""
    creator = FridaScriptCreatorWidget(main_app)
    creator.exec()
