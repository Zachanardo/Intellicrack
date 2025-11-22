"""Adobe Injector Tab - Native integration without Python conversion.

This module provides multiple integration methods for Adobe Injector
without converting the AutoIt3 code to Python.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import json
import subprocess
import threading
from collections.abc import Callable
from typing import Any

from intellicrack.core.adobe_injector_integration import AdobeInjectorWidget
from intellicrack.core.terminal_manager import get_terminal_manager
from intellicrack.handlers.pyqt6_handler import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.ui.tabs.base_tab import BaseTab
from intellicrack.utils.path_resolver import get_project_root


class AdobeInjectorTab(BaseTab):
    """Adobe Injector tab with multiple integration methods."""

    injector_started = pyqtSignal(str)
    patch_completed = pyqtSignal(bool, str)

    def __init__(
        self, shared_context: dict[str, Any] | None = None, parent: QWidget | None = None
    ) -> None:
        """Initialize Adobe Injector tab.

        Args:
            shared_context: Shared application context dictionary containing app_context, task_manager, and main_window.
            parent: Parent QWidget for this tab.

        """
        self.adobe_injector_process: subprocess.Popen[bytes] | None = None
        self.integration_method: str = "embedded"
        super().__init__(shared_context, parent)

    def setup_content(self) -> None:
        """Set up the Adobe Injector tab content."""
        layout = self.layout()

        # Integration method selector
        method_group = QGroupBox("Integration Method")
        method_layout = QHBoxLayout(method_group)

        method_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(
            [
                "Embedded Window (Native)",
                "Subprocess Control",
                "Terminal Execution",
                "DLL Injection",
                "AutoIt3X COM",
            ],
        )
        self.method_combo.currentTextChanged.connect(self.on_method_changed)

        method_layout.addWidget(self.method_combo)
        method_layout.addWidget(QLabel("Choose how to integrate Adobe Injector"))
        method_layout.addStretch()

        layout.addWidget(method_group)

        # Create tabbed interface for different methods
        self.method_tabs = QTabWidget()
        self.method_tabs.addTab(self.create_embedded_tab(), "Embedded")
        self.method_tabs.addTab(self.create_subprocess_tab(), "Subprocess")
        self.method_tabs.addTab(self.create_terminal_tab(), "Terminal")
        self.method_tabs.addTab(self.create_advanced_tab(), "Advanced")

        layout.addWidget(self.method_tabs)

    def create_embedded_tab(self) -> QWidget:
        """Create embedded window integration tab.

        Returns:
            QWidget: A tab widget containing the embedded Adobe Injector widget.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.embedded_widget = AdobeInjectorWidget()
        self.embedded_widget.status_updated.connect(self.on_status_update)
        layout.addWidget(self.embedded_widget)

        return tab

    def create_subprocess_tab(self) -> QWidget:
        """Create subprocess control tab.

        Returns:
            QWidget: A tab widget for controlling Adobe Injector via subprocess.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        control_group = QGroupBox("Subprocess Control")
        control_layout = QVBoxLayout(control_group)

        cmd_layout = QHBoxLayout()
        cmd_layout.addWidget(QLabel("Arguments:"))
        self.cmd_args = QLineEdit()
        self.cmd_args.setText("/silent /path:C:\\Program Files\\Adobe")
        cmd_layout.addWidget(self.cmd_args)

        control_layout.addLayout(cmd_layout)

        btn_layout = QHBoxLayout()

        launch_hidden_btn = QPushButton("Launch Hidden")
        launch_hidden_btn.clicked.connect(lambda: self.launch_subprocess(True))
        launch_hidden_btn.setStyleSheet("font-weight: bold; color: blue;")

        launch_visible_btn = QPushButton("Launch Visible")
        launch_visible_btn.clicked.connect(lambda: self.launch_subprocess(False))
        launch_visible_btn.setStyleSheet("font-weight: bold; color: green;")

        monitor_btn = QPushButton("Monitor Output")
        monitor_btn.clicked.connect(self.monitor_subprocess)

        btn_layout.addWidget(launch_hidden_btn)
        btn_layout.addWidget(launch_visible_btn)
        btn_layout.addWidget(monitor_btn)

        control_layout.addLayout(btn_layout)
        layout.addWidget(control_group)

        output_group = QGroupBox("Process Output")
        output_layout = QVBoxLayout(output_group)

        self.subprocess_output = QTextEdit()
        self.subprocess_output.setReadOnly(True)
        output_layout.addWidget(self.subprocess_output)

        layout.addWidget(output_group)

        return tab

    def create_terminal_tab(self) -> QWidget:
        """Create terminal execution tab.

        Returns:
            QWidget: A tab widget for executing commands in embedded terminal.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        terminal_group = QGroupBox("Terminal Execution")
        terminal_layout = QVBoxLayout(terminal_group)

        btn_layout = QHBoxLayout()

        scan_btn = QPushButton("Scan Adobe Products")
        scan_btn.clicked.connect(self.scan_in_terminal)
        scan_btn.setStyleSheet("font-weight: bold; color: blue;")

        patch_btn = QPushButton("Apply Patches")
        patch_btn.clicked.connect(self.patch_in_terminal)
        patch_btn.setStyleSheet("font-weight: bold; color: green;")

        custom_btn = QPushButton("Custom Command")
        custom_btn.clicked.connect(self.custom_terminal_command)

        btn_layout.addWidget(scan_btn)
        btn_layout.addWidget(patch_btn)
        btn_layout.addWidget(custom_btn)

        terminal_layout.addLayout(btn_layout)

        cmd_builder_layout = QHBoxLayout()
        cmd_builder_layout.addWidget(QLabel("Command:"))
        self.terminal_cmd = QLineEdit()
        self.terminal_cmd.setText("AdobeInjector.exe")
        cmd_builder_layout.addWidget(self.terminal_cmd)

        execute_btn = QPushButton("Execute")
        execute_btn.clicked.connect(self.execute_terminal_command)
        cmd_builder_layout.addWidget(execute_btn)

        terminal_layout.addLayout(cmd_builder_layout)
        layout.addWidget(terminal_group)

        terminal_output = QGroupBox("Terminal Output")
        terminal_output_layout = QVBoxLayout(terminal_output)

        self.terminal_display = QTextEdit()
        self.terminal_display.setReadOnly(True)
        self.terminal_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: Consolas, monospace;
                font-size: 10pt;
                border: 1px solid #444;
            }
        """)
        terminal_output_layout.addWidget(self.terminal_display)

        layout.addWidget(terminal_output)

        return tab

    def create_advanced_tab(self) -> QWidget:
        """Create advanced integration options tab.

        Returns:
            QWidget: A tab widget for advanced Adobe Injector options including DLL compilation, COM interface, resources, and silent configuration.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        dll_group = QGroupBox("DLL Compilation")
        dll_layout = QVBoxLayout(dll_group)

        compile_dll_btn = QPushButton("Compile Adobe Injector as DLL")
        compile_dll_btn.clicked.connect(self.compile_as_dll)
        compile_dll_btn.setToolTip("Compile AutoIt3 script as DLL for ctypes integration")

        dll_layout.addWidget(compile_dll_btn)
        dll_layout.addWidget(QLabel("Status: Not compiled"))

        layout.addWidget(dll_group)

        com_group = QGroupBox("AutoIt3X COM Interface")
        com_layout = QVBoxLayout(com_group)

        register_com_btn = QPushButton("Register AutoIt3X.dll")
        register_com_btn.clicked.connect(self.register_autoit_com)

        test_com_btn = QPushButton("Test COM Interface")
        test_com_btn.clicked.connect(self.test_com_interface)

        com_layout.addWidget(register_com_btn)
        com_layout.addWidget(test_com_btn)

        layout.addWidget(com_group)

        resource_group = QGroupBox("Resource Modification")
        resource_layout = QVBoxLayout(resource_group)

        extract_btn = QPushButton("Extract Resources")
        extract_btn.clicked.connect(self.extract_resources)

        modify_btn = QPushButton("Modify & Rebrand")
        modify_btn.clicked.connect(self.modify_resources)

        rebuild_btn = QPushButton("Rebuild Executable")
        rebuild_btn.clicked.connect(self.rebuild_executable)

        resource_layout.addWidget(extract_btn)
        resource_layout.addWidget(modify_btn)
        resource_layout.addWidget(rebuild_btn)

        layout.addWidget(resource_group)

        config_group = QGroupBox("Silent Mode Configuration")
        config_layout = QVBoxLayout(config_group)

        create_config_btn = QPushButton("Create Silent Config")
        create_config_btn.clicked.connect(self.create_silent_config)
        create_config_btn.setToolTip("Create configuration for fully automated patching")

        config_layout.addWidget(create_config_btn)

        layout.addWidget(config_group)
        layout.addStretch()

        return tab

    def launch_subprocess(self, hidden: bool = False) -> None:
        """Launch Adobe Injector as subprocess with control."""
        adobe_injector_path = get_project_root() / "tools/AdobeInjector/AdobeInjector.exe"

        if not adobe_injector_path.exists():
            self.subprocess_output.append(f"ERROR: {adobe_injector_path} not found")
            return

        try:
            cmd = [str(adobe_injector_path)]
            if args := self.cmd_args.text().strip():
                cmd.extend(args.split())

            if hidden:
                # Launch hidden with output capture
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

                # Validate that cmd contains only safe, expected commands
                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                    error_msg = f"Unsafe command: {cmd}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                cwd_str = (
                    str(adobe_injector_path.parent)
                    .replace(";", "")
                    .replace("|", "")
                    .replace("&", "")
                )
                self.adobe_injector_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    startupinfo=startupinfo,
                    cwd=cwd_str,
                    shell=False,
                )
                self.subprocess_output.append("Adobe Injector launched in hidden mode")

                # Start monitoring thread
                threading.Thread(target=self.monitor_subprocess, daemon=True).start()

            else:
                # Launch visible
                # Validate that cmd contains only safe, expected commands
                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                    error_msg = f"Unsafe command: {cmd}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                cwd_str = (
                    str(adobe_injector_path.parent)
                    .replace(";", "")
                    .replace("|", "")
                    .replace("&", "")
                )
                self.adobe_injector_process = subprocess.Popen(cmd, cwd=cwd_str, shell=False)
                self.subprocess_output.append("Adobe Injector launched in visible mode")

        except Exception as e:
            self.subprocess_output.append(f"ERROR: {e}")

    def monitor_subprocess(self) -> None:
        """Monitor subprocess output."""
        if not self.adobe_injector_process:
            return

        try:
            for line in iter(self.adobe_injector_process.stdout.readline, b""):
                if line:
                    self.subprocess_output.append(line.decode("utf-8", errors="ignore").strip())

            self.subprocess_output.append("Process terminated")

        except Exception as e:
            self.subprocess_output.append(f"Monitor error: {e}")

    def scan_in_terminal(self) -> None:
        """Run scan operation in terminal."""
        self.execute_in_terminal("AdobeInjector.exe /scan")

    def patch_in_terminal(self) -> None:
        """Run patch operation in terminal."""
        self.execute_in_terminal("AdobeInjector.exe /patch /silent")

    def custom_terminal_command(self) -> None:
        """Execute custom command in terminal."""
        if cmd := self.terminal_cmd.text():
            self.execute_in_terminal(cmd)

    def execute_terminal_command(self) -> None:
        """Execute command from input field."""
        self.custom_terminal_command()

    def execute_in_terminal(self, command: str) -> None:
        """Execute command in embedded terminal."""
        try:
            terminal_manager = get_terminal_manager()

            if not terminal_manager.is_terminal_available():
                self.terminal_display.append(
                    "Terminal not available. Please open Terminal tab first."
                )
                return

            adobe_injector_dir = get_project_root() / "tools/AdobeInjector"

            command_parts = command.split() if isinstance(command, str) else command
            session_id = terminal_manager.execute_command(
                command_parts,
                capture_output=False,
                auto_switch=True,
                cwd=str(adobe_injector_dir),
            )

            self.terminal_display.append(f"Executed in terminal: {command}")
            self.terminal_display.append(f"Session ID: {session_id}")
            self.injector_started.emit("Command sent to terminal")

        except Exception as e:
            self.terminal_display.append(f"Terminal error: {e}")

    def compile_as_dll(self) -> None:
        """Compile AutoIt3 script as DLL."""
        # This would use AutoIt3 compiler with DLL output option
        self.subprocess_output.append("DLL compilation requires AutoIt3 compiler with DLL support")

    def register_autoit_com(self) -> None:
        """Register AutoIt3X.dll for COM usage."""
        try:
            result = subprocess.run(
                ["regsvr32", "/s", "AutoIt3X.dll"], capture_output=True, text=True
            )
            if result.returncode == 0:
                self.subprocess_output.append("AutoIt3X.dll registered successfully")
            else:
                self.subprocess_output.append(f"Registration failed: {result.stderr}")
        except Exception as e:
            self.subprocess_output.append(f"Error: {e}")

    def test_com_interface(self) -> None:
        """Test AutoIt3X COM interface."""
        try:
            import win32com.client

            autoit = win32com.client.Dispatch("AutoItX3.Control")
            version = autoit.Version()
            self.subprocess_output.append(f"AutoIt3X COM Version: {version}")
        except Exception as e:
            self.subprocess_output.append(f"COM test failed: {e}")

    def extract_resources(self) -> None:
        """Extract resources from Adobe Injector executable."""
        self.subprocess_output.append("Resource extraction would use tools like ResourceHacker")

    def modify_resources(self) -> None:
        """Modify and rebrand resources."""
        # Create rebranding configuration
        rebrand = {
            "ProductName": "Adobe Injector",
            "CompanyName": "Intellicrack",
            "FileDescription": "Adobe License Bypass Module",
            "InternalName": "AdobeInjector",
            "LegalCopyright": "Intellicrack 2025",
            "OriginalFilename": "adobe_injector.exe",
        }

        config_path = get_project_root() / "tools/AdobeInjector/rebrand.json"
        with open(config_path, "w") as f:
            json.dump(rebrand, f, indent=2)

        self.subprocess_output.append(f"Rebranding configuration saved to {config_path}")

    def rebuild_executable(self) -> None:
        """Rebuild executable with modified resources."""
        self.subprocess_output.append("Rebuild would use AutoIt3Wrapper with custom resources")

    def create_silent_config(self) -> None:
        """Create configuration for silent/automated operation."""
        config = {
            "auto_scan": True,
            "auto_patch": True,
            "target_path": "C:\\Program Files\\Adobe",
            "backup_files": True,
            "block_hosts": True,
            "create_firewall_rules": True,
            "remove_ags": True,
            "silent_mode": True,
        }

        config_path = get_project_root() / "tools/AdobeInjector/silent_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        self.subprocess_output.append(f"Silent configuration created: {config_path}")

    def on_method_changed(self, method: str) -> None:
        """Handle integration method change."""
        method_map = {
            "Embedded Window (Native)": 0,
            "Subprocess Control": 1,
            "Terminal Execution": 2,
            "DLL Injection": 3,
            "AutoIt3X COM": 3,
        }

        if method in method_map:
            self.method_tabs.setCurrentIndex(method_map[method])

    def on_status_update(self, status: str) -> None:
        """Handle status updates from integration."""
        if hasattr(self, "subprocess_output"):
            self.subprocess_output.append(status)
        self.injector_started.emit(status)
