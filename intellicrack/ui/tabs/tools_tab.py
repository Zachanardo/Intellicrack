"""Tools tab for Intellicrack.

This module provides the tools interface for plugin management,
custom tool integration, and external tool execution.

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

import os
import subprocess
from pathlib import Path

from intellicrack.core.patching.windows_activator import WindowsActivator
from intellicrack.core.terminal_manager import get_terminal_manager
from intellicrack.handlers.pyqt6_handler import (
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.ui.tabs.adobe_injector_tab import AdobeInjectorTab
from intellicrack.utils.core.dependency_feedback import dependency_feedback, get_user_friendly_error
from intellicrack.utils.logger import logger

from .base_tab import BaseTab


class ToolsTab(BaseTab):
    """Tools tab consolidating tools, plugins, and network analysis."""

    tool_executed = pyqtSignal(str, str)
    plugin_loaded = pyqtSignal(str, bool)
    network_capture_started = pyqtSignal(str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize tools tab with external tool integration and management."""
        self.available_tools = {}
        self.loaded_plugins = {}
        self.network_interfaces = []
        self.current_binary = None
        self.current_binary_path = None
        super().__init__(shared_context, parent)

        # Connect to app_context signals for binary loading
        if self.app_context:
            self.app_context.binary_loaded.connect(self.on_binary_loaded)
            self.app_context.binary_unloaded.connect(self.on_binary_unloaded)

            # Check if a binary is already loaded
            current_binary = self.app_context.get_current_binary()
            if current_binary:
                self.on_binary_loaded(current_binary)

    def setup_content(self):
        """Setup the tools tab content."""
        layout = self.layout()  # Use existing layout from BaseTab

        # Convert to QHBoxLayout behavior by using a horizontal container
        h_container = QWidget()
        h_layout = QHBoxLayout(h_container)

        # Left panel - Tools and controls
        left_panel = self.create_tools_panel()

        # Right panel - Results and output
        right_panel = self.create_results_panel()

        # Add panels with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 40)
        splitter.setStretchFactor(1, 60)

        h_layout.addWidget(splitter)
        layout.addWidget(h_container)
        self.is_loaded = True

    def create_tools_panel(self):
        """Create the tools control panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Tools tabs
        self.tools_tabs = QTabWidget()
        self.tools_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Add tool categories
        self.tools_tabs.addTab(self.create_system_tools_tab(), "System Tools")
        self.tools_tabs.addTab(self.create_analysis_tools_tab(), "Analysis Tools")
        self.tools_tabs.addTab(self.create_advanced_analysis_tab(), "Advanced Analysis")
        self.tools_tabs.addTab(self.create_plugin_manager_tab(), "Plugin Manager")
        self.tools_tabs.addTab(self.create_network_tools_tab(), "Network Tools")
        self.tools_tabs.addTab(self.create_activation_tools_tab(), "Activation Tools")

        # Add Adobe Injector as sub-tab
        self.adobe_injector = AdobeInjectorTab(self.shared_context, self)
        self.tools_tabs.addTab(self.adobe_injector, "Adobe Injector")

        layout.addWidget(self.tools_tabs)
        return panel

    def create_system_tools_tab(self):
        """Create system tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # System Information
        system_group = QGroupBox("System Information")
        system_layout = QVBoxLayout(system_group)

        sys_info_btn = QPushButton("Get System Info")
        sys_info_btn.clicked.connect(self.get_system_info)
        sys_info_btn.setStyleSheet("font-weight: bold; color: blue;")

        process_list_btn = QPushButton("List Running Processes")
        process_list_btn.clicked.connect(self.list_processes)

        memory_info_btn = QPushButton("Memory Information")
        memory_info_btn.clicked.connect(self.get_memory_info)

        system_layout.addWidget(sys_info_btn)
        system_layout.addWidget(process_list_btn)
        system_layout.addWidget(memory_info_btn)

        # File Operations
        file_group = QGroupBox("File Operations")
        file_layout = QVBoxLayout(file_group)

        # File path input
        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(QLabel("File Path:"))
        self.file_path_edit = QLineEdit()
        browse_file_btn = QPushButton("Browse")
        browse_file_btn.clicked.connect(self.browse_file)

        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(browse_file_btn)

        # File operations buttons
        file_ops_layout = QHBoxLayout()

        self.file_info_btn = QPushButton("File Info")
        self.file_info_btn.clicked.connect(self.get_file_info)

        hex_dump_btn = QPushButton("Hex Dump")
        hex_dump_btn.clicked.connect(self.create_hex_dump)

        self.strings_btn = QPushButton("Extract Strings")
        self.strings_btn.clicked.connect(self.extract_strings)

        file_ops_layout.addWidget(self.file_info_btn)
        file_ops_layout.addWidget(hex_dump_btn)
        file_ops_layout.addWidget(self.strings_btn)

        file_layout.addLayout(file_path_layout)
        file_layout.addLayout(file_ops_layout)

        # Registry Tools (Windows)
        registry_group = QGroupBox("Registry Tools")
        registry_layout = QVBoxLayout(registry_group)

        reg_query_layout = QHBoxLayout()
        reg_query_layout.addWidget(QLabel("Registry Key:"))
        self.reg_key_edit = QLineEdit()
        self.reg_key_edit.setText("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
        reg_query_layout.addWidget(self.reg_key_edit)

        reg_query_btn = QPushButton("Query Registry")
        reg_query_btn.clicked.connect(self.query_registry)

        registry_layout.addLayout(reg_query_layout)
        registry_layout.addWidget(reg_query_btn)

        layout.addWidget(system_group)
        layout.addWidget(file_group)
        layout.addWidget(registry_group)
        layout.addStretch()

        return tab

    def create_analysis_tools_tab(self):
        """Create analysis tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Binary Analysis Tools
        binary_group = QGroupBox("Binary Analysis Tools")
        binary_layout = QVBoxLayout(binary_group)

        # Binary path
        binary_path_layout = QHBoxLayout()
        binary_path_layout.addWidget(QLabel("Binary:"))
        self.analysis_binary_edit = QLineEdit()
        browse_binary_btn = QPushButton("Browse")
        browse_binary_btn.clicked.connect(self.browse_analysis_binary)

        binary_path_layout.addWidget(self.analysis_binary_edit)
        binary_path_layout.addWidget(browse_binary_btn)

        # Analysis tools
        tools_layout = QGridLayout()

        disasm_btn = QPushButton("Disassemble")
        disasm_btn.clicked.connect(self.disassemble_binary)
        disasm_btn.setStyleSheet("font-weight: bold; color: green;")

        entropy_btn = QPushButton("Entropy Analysis")
        entropy_btn.clicked.connect(self.analyze_entropy)

        imports_btn = QPushButton("Import Analysis")
        imports_btn.clicked.connect(self.analyze_imports)

        exports_btn = QPushButton("Export Analysis")
        exports_btn.clicked.connect(self.analyze_exports)

        sections_btn = QPushButton("Section Analysis")
        sections_btn.clicked.connect(self.analyze_sections)

        symbols_btn = QPushButton("Symbol Analysis")
        symbols_btn.clicked.connect(self.analyze_symbols)

        tools_layout.addWidget(disasm_btn, 0, 0)
        tools_layout.addWidget(entropy_btn, 0, 1)
        tools_layout.addWidget(imports_btn, 1, 0)
        tools_layout.addWidget(exports_btn, 1, 1)
        tools_layout.addWidget(sections_btn, 2, 0)
        tools_layout.addWidget(symbols_btn, 2, 1)

        binary_layout.addLayout(binary_path_layout)
        binary_layout.addLayout(tools_layout)

        # Cryptographic Analysis
        crypto_group = QGroupBox("Cryptographic Analysis")
        crypto_layout = QVBoxLayout(crypto_group)

        # Input data
        crypto_input_layout = QVBoxLayout()
        crypto_input_layout.addWidget(QLabel("Input Data:"))
        self.crypto_input = QTextEdit()
        self.crypto_input.setMaximumHeight(80)
        crypto_input_layout.addWidget(self.crypto_input)

        # Crypto operations
        crypto_ops_layout = QHBoxLayout()

        hash_md5_btn = QPushButton("MD5 Hash")
        hash_md5_btn.clicked.connect(lambda: self.calculate_hash("md5"))

        hash_sha256_btn = QPushButton("SHA256 Hash")
        hash_sha256_btn.clicked.connect(lambda: self.calculate_hash("sha256"))

        base64_encode_btn = QPushButton("Base64 Encode")
        base64_encode_btn.clicked.connect(self.base64_encode)

        base64_decode_btn = QPushButton("Base64 Decode")
        base64_decode_btn.clicked.connect(self.base64_decode)

        crypto_ops_layout.addWidget(hash_md5_btn)
        crypto_ops_layout.addWidget(hash_sha256_btn)
        crypto_ops_layout.addWidget(base64_encode_btn)
        crypto_ops_layout.addWidget(base64_decode_btn)

        crypto_layout.addLayout(crypto_input_layout)
        crypto_layout.addLayout(crypto_ops_layout)

        layout.addWidget(binary_group)
        layout.addWidget(crypto_group)
        layout.addStretch()

        return tab

    def create_plugin_manager_tab(self):
        """Create plugin manager tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Plugin List
        plugin_list_group = QGroupBox("Available Plugins")
        plugin_list_layout = QVBoxLayout(plugin_list_group)

        self.plugin_list = QListWidget()
        self.populate_plugin_list()
        plugin_list_layout.addWidget(self.plugin_list)

        # Plugin controls
        plugin_controls_layout = QHBoxLayout()

        load_plugin_btn = QPushButton("Load Plugin")
        load_plugin_btn.clicked.connect(self.load_selected_plugin)
        load_plugin_btn.setStyleSheet("font-weight: bold; color: green;")

        unload_plugin_btn = QPushButton("Unload Plugin")
        unload_plugin_btn.clicked.connect(self.unload_selected_plugin)
        unload_plugin_btn.setStyleSheet("color: red;")

        reload_plugin_btn = QPushButton("Reload Plugin")
        reload_plugin_btn.clicked.connect(self.reload_selected_plugin)

        plugin_controls_layout.addWidget(load_plugin_btn)
        plugin_controls_layout.addWidget(unload_plugin_btn)
        plugin_controls_layout.addWidget(reload_plugin_btn)

        # Plugin Information
        plugin_info_group = QGroupBox("Plugin Information")
        plugin_info_layout = QVBoxLayout(plugin_info_group)

        self.plugin_info_text = QTextEdit()
        self.plugin_info_text.setMaximumHeight(150)
        self.plugin_info_text.setReadOnly(True)
        plugin_info_layout.addWidget(self.plugin_info_text)

        # Plugin Creation
        plugin_create_group = QGroupBox("Plugin Development")
        plugin_create_layout = QVBoxLayout(plugin_create_group)

        create_plugin_btn = QPushButton("Create New Plugin")
        create_plugin_btn.clicked.connect(self.create_new_plugin)
        create_plugin_btn.setStyleSheet("font-weight: bold; color: blue;")

        edit_plugin_btn = QPushButton("Edit Selected Plugin")
        edit_plugin_btn.clicked.connect(self.edit_selected_plugin)

        plugin_dev_layout = QHBoxLayout()
        plugin_dev_layout.addWidget(create_plugin_btn)
        plugin_dev_layout.addWidget(edit_plugin_btn)

        plugin_create_layout.addLayout(plugin_dev_layout)

        layout.addWidget(plugin_list_group)
        layout.addLayout(plugin_controls_layout)
        layout.addWidget(plugin_info_group)
        layout.addWidget(plugin_create_group)

        return tab

    def create_network_tools_tab(self):
        """Create network tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Network Interface Selection
        interface_group = QGroupBox("Network Interface")
        interface_layout = QVBoxLayout(interface_group)

        interface_select_layout = QHBoxLayout()
        interface_select_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.populate_network_interfaces()
        interface_select_layout.addWidget(self.interface_combo)

        refresh_interfaces_btn = QPushButton("Refresh")
        refresh_interfaces_btn.clicked.connect(self.populate_network_interfaces)
        interface_select_layout.addWidget(refresh_interfaces_btn)

        interface_layout.addLayout(interface_select_layout)

        # Packet Capture
        capture_group = QGroupBox("Packet Capture")
        capture_layout = QVBoxLayout(capture_group)

        # Capture filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.capture_filter_edit = QLineEdit()
        self.capture_filter_edit.setText("tcp port 443")
        filter_layout.addWidget(self.capture_filter_edit)

        # Capture controls
        capture_controls_layout = QHBoxLayout()

        start_capture_btn = QPushButton("Start Capture")
        start_capture_btn.clicked.connect(self.start_packet_capture)
        start_capture_btn.setStyleSheet("font-weight: bold; color: green;")

        stop_capture_btn = QPushButton("Stop Capture")
        stop_capture_btn.clicked.connect(self.stop_packet_capture)
        stop_capture_btn.setStyleSheet("color: red;")

        save_capture_btn = QPushButton("Save Capture")
        save_capture_btn.clicked.connect(self.save_packet_capture)

        capture_controls_layout.addWidget(start_capture_btn)
        capture_controls_layout.addWidget(stop_capture_btn)
        capture_controls_layout.addWidget(save_capture_btn)

        capture_layout.addLayout(filter_layout)
        capture_layout.addLayout(capture_controls_layout)

        # Network Scanning
        scan_group = QGroupBox("Network Scanning")
        scan_layout = QVBoxLayout(scan_group)

        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.scan_target_edit = QLineEdit()
        self.scan_target_edit.setText("127.0.0.1")
        target_layout.addWidget(self.scan_target_edit)

        # Scan types
        scan_types_layout = QHBoxLayout()

        ping_scan_btn = QPushButton("Ping Scan")
        ping_scan_btn.clicked.connect(self.ping_scan)

        port_scan_btn = QPushButton("Port Scan")
        port_scan_btn.clicked.connect(self.port_scan)

        service_scan_btn = QPushButton("Service Scan")
        service_scan_btn.clicked.connect(self.service_scan)

        scan_types_layout.addWidget(ping_scan_btn)
        scan_types_layout.addWidget(port_scan_btn)
        scan_types_layout.addWidget(service_scan_btn)

        scan_layout.addLayout(target_layout)
        scan_layout.addLayout(scan_types_layout)

        layout.addWidget(interface_group)
        layout.addWidget(capture_group)
        layout.addWidget(scan_group)
        layout.addStretch()

        return tab

    def create_activation_tools_tab(self):
        """Create activation tools tab for Windows activation."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        windows_group = QGroupBox("Windows Activation")
        windows_layout = QVBoxLayout(windows_group)

        self.windows_activation_status = QLabel("Status: Unknown")
        self.windows_activation_status.setStyleSheet("font-weight: bold;")
        windows_layout.addWidget(self.windows_activation_status)

        check_windows_btn = QPushButton("Check Windows Activation Status")
        check_windows_btn.clicked.connect(self.check_windows_activation)
        windows_layout.addWidget(check_windows_btn)

        activate_windows_btn = QPushButton("Activate Windows (Interactive)")
        activate_windows_btn.setStyleSheet("font-weight: bold; color: green; padding: 10px;")
        activate_windows_btn.clicked.connect(self.activate_windows_interactive)
        windows_layout.addWidget(activate_windows_btn)

        help_text = QLabel("Launches WindowsActivator.cmd in embedded terminal.\nYou can select activation method in the menu.")
        help_text.setStyleSheet("color: gray; font-style: italic;")
        windows_layout.addWidget(help_text)

        layout.addWidget(windows_group)

        layout.addStretch()
        return tab

    def check_windows_activation(self):
        """Check current Windows activation status."""
        try:
            activator = WindowsActivator()
            status = activator.get_activation_status()

            status_text = status.get("status", "unknown")
            self.windows_activation_status.setText(f"Status: {status_text}")

            if status_text == "activated":
                self.windows_activation_status.setStyleSheet("font-weight: bold; color: green;")
            else:
                self.windows_activation_status.setStyleSheet("font-weight: bold; color: orange;")

            if hasattr(self.parent(), "append_output"):
                self.parent().append_output(f"Windows Activation Status: {status_text}")
                if "raw_output" in status:
                    self.parent().append_output(status["raw_output"])

        except Exception as e:
            self.windows_activation_status.setText("Status: Error checking")
            self.windows_activation_status.setStyleSheet("font-weight: bold; color: red;")
            if hasattr(self.parent(), "append_output"):
                self.parent().append_output(f"Error checking Windows activation: {e}")

    def activate_windows_interactive(self):
        """Launch Windows activation in embedded terminal."""
        try:
            terminal_mgr = get_terminal_manager()

            script_path = "Windows_Patch/WindowsActivator.cmd"

            terminal_mgr.execute_script(script_path=script_path, interactive=True, auto_switch=True)

            self.windows_activation_status.setText("Status: Activation in progress...")
            self.windows_activation_status.setStyleSheet("font-weight: bold; color: blue;")

        except Exception as e:
            self.windows_activation_status.setText("Status: Error launching")
            self.windows_activation_status.setStyleSheet("font-weight: bold; color: red;")

            if hasattr(self.parent(), "append_output"):
                self.parent().append_output(f"Error launching Windows activation: {e}")

    def create_advanced_analysis_tab(self):
        """Create advanced analysis tools tab with sophisticated backend integration."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Binary path for advanced analysis
        binary_path_layout = QHBoxLayout()
        binary_path_layout.addWidget(QLabel("Target Binary:"))
        self.advanced_binary_edit = QLineEdit()
        browse_advanced_btn = QPushButton("Browse")
        browse_advanced_btn.clicked.connect(self.browse_advanced_binary)
        binary_path_layout.addWidget(self.advanced_binary_edit)
        binary_path_layout.addWidget(browse_advanced_btn)

        # Dynamic Analysis Tools
        dynamic_group = QGroupBox("Dynamic Analysis & Instrumentation")
        dynamic_layout = QGridLayout(dynamic_group)

        frida_analysis_btn = QPushButton("Frida Analysis")
        frida_analysis_btn.clicked.connect(self.run_frida_analysis)
        frida_analysis_btn.setStyleSheet("font-weight: bold; color: #FF6B35;")
        frida_analysis_btn.setToolTip(
            "Dynamic binary instrumentation framework for real-time code injection, API hooking, and runtime manipulation"
        )

        symbolic_exec_btn = QPushButton("Symbolic Execution")
        symbolic_exec_btn.clicked.connect(self.run_symbolic_execution)
        symbolic_exec_btn.setStyleSheet("font-weight: bold; color: #2E86AB;")
        symbolic_exec_btn.setToolTip(
            "Explore multiple execution paths simultaneously using symbolic values to discover vulnerabilities and edge cases"
        )

        memory_forensics_btn = QPushButton("Memory Forensics")
        memory_forensics_btn.clicked.connect(self.run_memory_forensics)
        memory_forensics_btn.setToolTip(
            "Analyze memory dumps, heap structures, and runtime memory patterns for hidden data and exploitation vectors"
        )

        dynamic_layout.addWidget(frida_analysis_btn, 0, 0)
        dynamic_layout.addWidget(symbolic_exec_btn, 0, 1)
        dynamic_layout.addWidget(memory_forensics_btn, 1, 0)

        # Advanced Static Analysis
        static_group = QGroupBox("Advanced Static Analysis")
        static_layout = QGridLayout(static_group)

        ghidra_analysis_btn = QPushButton("Ghidra Analysis")
        ghidra_analysis_btn.clicked.connect(self.run_ghidra_analysis)
        ghidra_analysis_btn.setStyleSheet("font-weight: bold; color: #7209B7;")
        ghidra_analysis_btn.setToolTip(
            "NSA's reverse engineering suite for decompilation, control flow analysis, and cross-references mapping"
        )

        protection_scan_btn = QPushButton("Protection Scanner")
        protection_scan_btn.clicked.connect(self.run_protection_scanner)
        protection_scan_btn.setStyleSheet("font-weight: bold; color: #F72585;")
        protection_scan_btn.setToolTip("Detect and identify packers, protectors, obfuscators, and anti-tampering mechanisms in binaries")

        vulnerability_scan_btn = QPushButton("Vulnerability Engine")
        vulnerability_scan_btn.clicked.connect(self.run_vulnerability_engine)
        vulnerability_scan_btn.setToolTip(
            "Automated vulnerability scanning for buffer overflows, format strings, race conditions, and common weaknesses"
        )

        taint_analysis_btn = QPushButton("Taint Analysis")
        taint_analysis_btn.clicked.connect(self.run_taint_analysis)
        taint_analysis_btn.setToolTip(
            "Track data flow from untrusted sources to critical sinks to identify potential security vulnerabilities"
        )

        static_layout.addWidget(ghidra_analysis_btn, 0, 0)
        static_layout.addWidget(protection_scan_btn, 0, 1)
        static_layout.addWidget(vulnerability_scan_btn, 1, 0)
        static_layout.addWidget(taint_analysis_btn, 1, 1)

        # AI-Powered Analysis
        ai_group = QGroupBox("AI-Powered Analysis")
        ai_layout = QGridLayout(ai_group)

        ai_script_gen_btn = QPushButton("AI Script Generator")
        ai_script_gen_btn.clicked.connect(self.run_ai_script_generator)
        ai_script_gen_btn.setStyleSheet("font-weight: bold; color: #4361EE;")
        ai_script_gen_btn.setToolTip("Generate custom Frida, Ghidra, and IDA Pro scripts using AI based on your analysis requirements")

        semantic_analysis_btn = QPushButton("Semantic Analysis")
        semantic_analysis_btn.clicked.connect(self.run_semantic_analysis)
        semantic_analysis_btn.setToolTip(
            "Use AI to understand code intent, identify algorithms, and recognize design patterns in decompiled code"
        )

        pattern_analysis_btn = QPushButton("Pattern Analysis")
        pattern_analysis_btn.clicked.connect(self.run_pattern_analysis)
        pattern_analysis_btn.setToolTip(
            "Machine learning-based detection of cryptographic routines, licensing checks, and protection patterns"
        )

        ai_layout.addWidget(ai_script_gen_btn, 0, 0)
        ai_layout.addWidget(semantic_analysis_btn, 0, 1)
        ai_layout.addWidget(pattern_analysis_btn, 1, 0)

        # Exploitation Tools
        exploit_group = QGroupBox("Exploitation & Payload Generation")
        exploit_layout = QGridLayout(exploit_group)

        rop_generator_btn = QPushButton("ROP Generator")
        rop_generator_btn.clicked.connect(self.run_rop_generator)
        rop_generator_btn.setStyleSheet("font-weight: bold; color: #D00000;")
        rop_generator_btn.setToolTip("Automatically generate Return-Oriented Programming chains to bypass DEP/NX protections")

        payload_engine_btn = QPushButton("Payload Engine")
        payload_engine_btn.clicked.connect(self.run_payload_engine)
        payload_engine_btn.setStyleSheet("font-weight: bold; color: #FF8500;")
        payload_engine_btn.setToolTip(
            "Create, encode, and obfuscate exploitation payloads with bad character avoidance and size optimization"
        )

        shellcode_gen_btn = QPushButton("Shellcode Generator")
        shellcode_gen_btn.clicked.connect(self.run_shellcode_generator)
        shellcode_gen_btn.setToolTip("Generate position-independent shellcode for various architectures with customizable functionality")

        exploit_layout.addWidget(rop_generator_btn, 0, 0)
        exploit_layout.addWidget(payload_engine_btn, 0, 1)
        exploit_layout.addWidget(shellcode_gen_btn, 1, 0)

        # Network Analysis
        network_group = QGroupBox("Network & Traffic Analysis")
        network_layout = QGridLayout(network_group)

        traffic_analysis_btn = QPushButton("Traffic Analysis")
        traffic_analysis_btn.clicked.connect(self.run_traffic_analysis)
        traffic_analysis_btn.setToolTip(
            "Capture and analyze network traffic to identify license servers, API calls, and communication protocols"
        )

        protocol_analysis_btn = QPushButton("Protocol Fingerprinting")
        protocol_analysis_btn.clicked.connect(self.run_protocol_analysis)
        protocol_analysis_btn.setToolTip(
            "Identify and decode proprietary protocols, license verification schemes, and encrypted communications"
        )

        network_layout.addWidget(traffic_analysis_btn, 0, 0)
        network_layout.addWidget(protocol_analysis_btn, 0, 1)

        # Add all groups to layout
        layout.addLayout(binary_path_layout)
        layout.addWidget(dynamic_group)
        layout.addWidget(static_group)
        layout.addWidget(ai_group)
        layout.addWidget(exploit_group)
        layout.addWidget(network_group)
        layout.addStretch()

        return tab

    def create_results_panel(self):
        """Create the results panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFont(QFont("Consolas", 10))

        # Tool output viewer
        self.tool_output = QTextEdit()
        self.tool_output.setReadOnly(True)
        self.tool_output.setFont(QFont("Consolas", 10))

        # Network packets table
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(6)
        self.packets_table.setHorizontalHeaderLabels(
            [
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Info",
            ]
        )
        self.packets_table.horizontalHeader().setStretchLastSection(True)

        # Plugin output
        self.plugin_output = QTextEdit()
        self.plugin_output.setReadOnly(True)
        self.plugin_output.setFont(QFont("Consolas", 10))

        self.results_tabs.addTab(self.output_console, "Console")
        self.results_tabs.addTab(self.tool_output, "Tool Output")
        self.results_tabs.addTab(self.packets_table, "Network Packets")
        self.results_tabs.addTab(self.plugin_output, "Plugin Output")

        layout.addWidget(self.results_tabs)
        return panel

    def on_binary_loaded(self, binary_info):
        """Handle binary loaded signal from app_context."""
        if isinstance(binary_info, dict):
            self.current_binary = binary_info.get("name", "Unknown")
            self.current_binary_path = binary_info.get("path")

            # Update file path in file operations if available
            if hasattr(self, "file_path_edit"):
                self.file_path_edit.setText(self.current_binary_path)

            # Enable analysis tools that require a binary
            self.enable_binary_dependent_tools(True)

            # Log the event
            if hasattr(self, "tool_output"):
                self.tool_output.append(f"[INFO] Binary loaded: {self.current_binary}")

    def on_binary_unloaded(self):
        """Handle binary unloaded signal from app_context."""
        self.current_binary = None
        self.current_binary_path = None

        # Clear file path
        if hasattr(self, "file_path_edit"):
            self.file_path_edit.clear()

        # Disable analysis tools that require a binary
        self.enable_binary_dependent_tools(False)

        # Log the event
        if hasattr(self, "tool_output"):
            self.tool_output.append("[INFO] Binary unloaded")

    def enable_binary_dependent_tools(self, enabled):
        """Enable or disable tools that require a loaded binary."""
        # List of buttons that require a binary to be loaded
        binary_dependent_buttons = [
            "file_info_btn",
            "file_hash_btn",
            "strings_btn",
            "disassemble_btn",
            "decompile_btn",
            "ida_btn",
            "ghidra_btn",
            "radare2_btn",
            "x64dbg_btn",
        ]

        for btn_name in binary_dependent_buttons:
            if hasattr(self, btn_name):
                btn = getattr(self, btn_name)
                btn.setEnabled(enabled)

    def get_system_info(self):
        """Get system information."""
        try:
            import platform

            from intellicrack.handlers.psutil_handler import psutil

            info = []
            info.append(f"System: {platform.system()}")
            info.append(f"Release: {platform.release()}")
            info.append(f"Version: {platform.version()}")
            info.append(f"Machine: {platform.machine()}")
            info.append(f"Processor: {platform.processor()}")
            info.append(f"CPU Cores: {psutil.cpu_count(logical=False)}")
            info.append(f"Memory: {psutil.virtual_memory().total // (1024**3)} GB")

            self.output_console.append("\n".join(info))
            self.log_message("System information retrieved")

        except Exception as e:
            self.output_console.append(f"Error getting system info: {e!s}")

    def list_processes(self):
        """List running processes."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            processes = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    proc_info = proc.info
                    processes.append(
                        f"PID: {proc_info['pid']:>6} | "
                        f"Name: {proc_info['name']:<20} | "
                        f"CPU: {proc_info['cpu_percent']:>5.1f}% | "
                        f"Memory: {proc_info['memory_percent']:>5.1f}%"
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            self.output_console.append("Running Processes:")
            self.output_console.append("-" * 60)
            for proc in processes[:50]:  # Limit to first 50 processes
                self.output_console.append(proc)

            self.log_message(f"Listed {len(processes)} running processes")

        except Exception as e:
            self.output_console.append(f"Error listing processes: {e!s}")

    def get_memory_info(self):
        """Get memory information."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            info = []
            info.append(f"Total Memory: {memory.total // (1024**3)} GB")
            info.append(f"Available Memory: {memory.available // (1024**3)} GB")
            info.append(f"Used Memory: {memory.used // (1024**3)} GB")
            info.append(f"Memory Usage: {memory.percent}%")
            info.append(f"Total Swap: {swap.total // (1024**3)} GB")
            info.append(f"Used Swap: {swap.used // (1024**3)} GB")
            info.append(f"Swap Usage: {swap.percent}%")

            self.output_console.append("Memory Information:")
            self.output_console.append("\n".join(info))
            self.log_message("Memory information retrieved")

        except Exception as e:
            self.output_console.append(f"Error getting memory info: {e!s}")

    def browse_file(self):
        """Browse for file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Analysis",
            "",
            "All Files (*)",
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self.log_message(f"File selected: {file_path}")

    def get_file_info(self):
        """Get file information."""
        file_path = self.file_path_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            self.output_console.append("Error: Invalid file path")
            return

        try:
            import stat
            from datetime import datetime

            file_stat = os.stat(file_path)

            info = []
            info.append(f"File: {os.path.basename(file_path)}")
            info.append(f"Path: {file_path}")
            info.append(f"Size: {file_stat.st_size} bytes ({file_stat.st_size / (1024**2):.2f} MB)")
            info.append(f"Created: {datetime.fromtimestamp(file_stat.st_ctime)}")
            info.append(f"Modified: {datetime.fromtimestamp(file_stat.st_mtime)}")
            info.append(f"Accessed: {datetime.fromtimestamp(file_stat.st_atime)}")
            info.append(f"Mode: {stat.filemode(file_stat.st_mode)}")

            self.tool_output.append("File Information:")
            self.tool_output.append("\n".join(info))
            self.log_message("File information retrieved")

        except Exception as e:
            self.output_console.append(f"Error getting file info: {e!s}")

    def create_hex_dump(self):
        """Create hex dump of file."""
        file_path = self.file_path_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            self.output_console.append("Error: Invalid file path")
            return

        try:
            with open(file_path, "rb") as f:
                data = f.read(1024)  # Read first 1KB

            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_lines.append(f"{i:08x}: {hex_part:<48} |{ascii_part}|")

            self.tool_output.append("Hex Dump (first 1KB):")
            self.tool_output.append("\n".join(hex_lines))
            self.log_message("Hex dump created")

        except Exception as e:
            self.output_console.append(f"Error creating hex dump: {e!s}")

    def extract_strings(self):
        """Extract strings from file."""
        file_path = self.file_path_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            self.output_console.append("Error: Invalid file path")
            return

        try:
            import re

            with open(file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings (minimum length 4)
            ascii_strings = re.findall(b"[!-~]{4,}", data)
            unicode_strings = re.findall(b"(?:[!-~]\x00){4,}", data)

            self.tool_output.append("Extracted Strings:")
            self.tool_output.append("-" * 40)

            self.tool_output.append("ASCII Strings:")
            for s in ascii_strings[:100]:  # Limit to first 100
                try:
                    self.tool_output.append(s.decode("ascii"))
                except UnicodeDecodeError:
                    # Skip non-ASCII strings silently as expected
                    continue

            if unicode_strings:
                self.tool_output.append("\nUnicode Strings:")
                for s in unicode_strings[:50]:  # Limit to first 50
                    try:
                        decoded = s.decode("utf-16le")
                        self.tool_output.append(decoded)
                    except UnicodeDecodeError:
                        # Skip non-UTF-16 strings silently as expected
                        continue

            self.log_message(f"Extracted {len(ascii_strings)} ASCII and {len(unicode_strings)} Unicode strings")

        except Exception as e:
            self.output_console.append(f"Error extracting strings: {e!s}")

    def query_registry(self):
        """Query Windows registry."""
        reg_key = self.reg_key_edit.text().strip()
        if not reg_key:
            self.output_console.append("Error: No registry key specified")
            return

        try:
            import winreg

            # Parse registry hive
            if reg_key.startswith("HKEY_LOCAL_MACHINE"):
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey = reg_key.replace("HKEY_LOCAL_MACHINE\\", "")
            elif reg_key.startswith("HKEY_CURRENT_USER"):
                hive = winreg.HKEY_CURRENT_USER
                subkey = reg_key.replace("HKEY_CURRENT_USER\\", "")
            else:
                self.output_console.append("Error: Unsupported registry hive")
                return

            with winreg.OpenKey(hive, subkey) as key:
                values = []
                try:
                    i = 0
                    while True:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        values.append(f"{name}: {value} (Type: {reg_type})")
                        i += 1
                except OSError:
                    pass

                self.tool_output.append(f"Registry Key: {reg_key}")
                self.tool_output.append("-" * 40)
                for value in values:
                    self.tool_output.append(value)

                self.log_message(f"Queried registry key: {reg_key}")

        except Exception as e:
            self.output_console.append(f"Error querying registry: {e!s}")

    def browse_analysis_binary(self):
        """Browse for binary to analyze."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary for Analysis",
            "",
            "Executable Files (*.exe *.dll *.so);;All Files (*)",
        )

        if file_path:
            self.analysis_binary_edit.setText(file_path)
            self.log_message(f"Analysis binary selected: {file_path}")

    def disassemble_binary(self):
        """Disassemble binary using external tools."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            # Try using objdump first - validate binary path
            if not Path(binary_path).exists():
                self.log_message(f"Binary file not found: {binary_path}")
                return

            result = subprocess.run(  # nosec B603 B607 - objdump is a legitimate analysis tool  # noqa: S603
                ["objdump", "-d", str(binary_path)],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.tool_output.append("Disassembly Output:")
                self.tool_output.append("-" * 40)
                lines = result.stdout.split("\n")[:200]  # Limit output
                self.tool_output.append("\n".join(lines))
                self.log_message("Binary disassembled successfully")
            else:
                self.output_console.append(f"Disassembly failed: {result.stderr}")

        except FileNotFoundError:
            self.output_console.append("Error: objdump not found. Please install binutils.")
        except subprocess.TimeoutExpired:
            self.output_console.append("Error: Disassembly timed out")
        except Exception as e:
            self.output_console.append(f"Error disassembling binary: {e!s}")

    def analyze_entropy(self):
        """Analyze binary entropy."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            import math
            from collections import Counter

            with open(binary_path, "rb") as f:
                data = f.read()

            # Calculate entropy
            byte_counts = Counter(data)
            entropy = 0
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)

            # Analyze sections (simplified)
            chunk_size = len(data) // 10
            section_entropies = []

            for i in range(0, len(data), chunk_size):
                chunk = data[i : i + chunk_size]
                if len(chunk) > 0:
                    chunk_counts = Counter(chunk)
                    chunk_entropy = 0
                    for count in chunk_counts.values():
                        probability = count / len(chunk)
                        chunk_entropy -= probability * math.log2(probability)
                    section_entropies.append(chunk_entropy)

            self.tool_output.append("Entropy Analysis:")
            self.tool_output.append("-" * 40)
            self.tool_output.append(f"Overall Entropy: {entropy:.4f}")
            self.tool_output.append(f"File Size: {len(data)} bytes")
            self.tool_output.append("Section Entropies:")

            for i, ent in enumerate(section_entropies):
                self.tool_output.append(f"  Section {i + 1}: {ent:.4f}")

            # Interpretation
            if entropy > 7.5:
                self.tool_output.append("\nInterpretation: HIGH entropy - likely packed/encrypted")
            elif entropy > 6.5:
                self.tool_output.append("\nInterpretation: MEDIUM entropy - possibly compressed")
            else:
                self.tool_output.append("\nInterpretation: LOW entropy - likely not packed")

            self.log_message("Entropy analysis completed")

        except Exception as e:
            self.output_console.append(f"Error analyzing entropy: {e!s}")

    def analyze_imports(self):
        """Analyze binary imports."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Import Analysis:")
            self.tool_output.append("-" * 40)

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8")
                    self.tool_output.append(f"\nDLL: {dll_name}")

                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8")
                            self.tool_output.append(f"  - {func_name}")
                        else:
                            self.tool_output.append(f"  - Ordinal: {imp.ordinal}")
            else:
                self.tool_output.append("No imports found")

            self.log_message("Import analysis completed")

        except ImportError:
            self.output_console.append("Error: pefile module not available")
        except Exception as e:
            self.output_console.append(f"Error analyzing imports: {e!s}")

    def analyze_exports(self):
        """Analyze binary exports."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Export Analysis:")
            self.tool_output.append("-" * 40)

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                export_dir = pe.DIRECTORY_ENTRY_EXPORT
                self.tool_output.append(f"Export DLL Name: {export_dir.name.decode('utf-8')}")
                self.tool_output.append(f"Number of Functions: {export_dir.struct.NumberOfFunctions}")
                self.tool_output.append(f"Number of Names: {export_dir.struct.NumberOfNames}")
                self.tool_output.append("\nExported Functions:")

                for exp in export_dir.symbols:
                    if exp.name:
                        func_name = exp.name.decode("utf-8")
                        self.tool_output.append(f"  {exp.ordinal}: {func_name} (RVA: 0x{exp.address:08x})")
                    else:
                        self.tool_output.append(f"  {exp.ordinal}: <no name> (RVA: 0x{exp.address:08x})")
            else:
                self.tool_output.append("No exports found")

            self.log_message("Export analysis completed")

        except ImportError:
            self.output_console.append("Error: pefile module not available")
        except Exception as e:
            self.output_console.append(f"Error analyzing exports: {e!s}")

    def analyze_sections(self):
        """Analyze binary sections."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            from intellicrack.handlers.pefile_handler import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Section Analysis:")
            self.tool_output.append("-" * 60)
            self.tool_output.append(f"{'Name':<8} {'VirtAddr':<10} {'VirtSize':<10} {'RawAddr':<10} {'RawSize':<10} {'Characteristics'}")
            self.tool_output.append("-" * 60)

            for section in pe.sections:
                name = section.Name.decode("utf-8").rstrip("\x00")
                virt_addr = f"0x{section.VirtualAddress:08x}"
                virt_size = f"0x{section.Misc_VirtualSize:08x}"
                raw_addr = f"0x{section.PointerToRawData:08x}"
                raw_size = f"0x{section.SizeOfRawData:08x}"
                chars = f"0x{section.Characteristics:08x}"

                self.tool_output.append(f"{name:<8} {virt_addr:<10} {virt_size:<10} {raw_addr:<10} {raw_size:<10} {chars}")

            self.log_message("Section analysis completed")

        except ImportError:
            self.output_console.append("Error: pefile module not available")
        except Exception as e:
            self.output_console.append(f"Error analyzing sections: {e!s}")

    def analyze_symbols(self):
        """Analyze binary symbols."""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            # Try using nm tool for symbol analysis
            result = subprocess.run(  # nosec B603 B607 - nm is a legitimate analysis tool  # noqa: S603
                ["nm", str(binary_path)],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.tool_output.append("Symbol Analysis:")
                self.tool_output.append("-" * 40)
                lines = result.stdout.split("\n")[:200]  # Limit output
                for line in lines:
                    if line.strip():
                        self.tool_output.append(line)
                self.log_message("Symbol analysis completed")
            else:
                self.output_console.append("No symbols found or nm tool unavailable")

        except FileNotFoundError:
            self.output_console.append("Error: nm tool not found")
        except subprocess.TimeoutExpired:
            self.output_console.append("Error: Symbol analysis timed out")
        except Exception as e:
            self.output_console.append(f"Error analyzing symbols: {e!s}")

    def calculate_hash(self, algorithm):
        """Calculate hash of input data."""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import hashlib

            data_bytes = data.encode("utf-8")

            if algorithm == "md5":
                hash_obj = hashlib.sha256(data_bytes)  # Using SHA-256 for security
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256(data_bytes)
            else:
                self.output_console.append(f"Error: Unsupported hash algorithm: {algorithm}")
                return

            hash_value = hash_obj.hexdigest()
            self.tool_output.append(f"{algorithm.upper()} Hash: {hash_value}")
            self.log_message(f"{algorithm.upper()} hash calculated")

        except Exception as e:
            self.output_console.append(f"Error calculating hash: {e!s}")

    def base64_encode(self):
        """Base64 encode input data."""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import base64

            data_bytes = data.encode("utf-8")
            encoded = base64.b64encode(data_bytes).decode("utf-8")

            self.tool_output.append(f"Base64 Encoded: {encoded}")
            self.log_message("Base64 encoding completed")

        except Exception as e:
            self.output_console.append(f"Error encoding data: {e!s}")

    def base64_decode(self):
        """Base64 decode input data."""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import base64

            decoded_bytes = base64.b64decode(data)
            decoded = decoded_bytes.decode("utf-8")

            self.tool_output.append(f"Base64 Decoded: {decoded}")
            self.log_message("Base64 decoding completed")

        except Exception as e:
            self.output_console.append(f"Error decoding data: {e!s}")

    def populate_plugin_list(self):
        """Populate the plugin list."""
        self.plugin_list.clear()

        # Look for plugins in the plugins directory
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "intellicrack", "plugins", "custom_modules")

        if os.path.exists(plugins_dir):
            for file in os.listdir(plugins_dir):
                if file.endswith(".py") and not file.startswith("__"):
                    plugin_name = file[:-3]  # Remove .py extension
                    item = QListWidgetItem(plugin_name)

                    # Set status based on whether plugin is loaded
                    if plugin_name in self.loaded_plugins:
                        item.setBackground(QColor(200, 255, 200))  # Light green for loaded
                        item.setText(f"{plugin_name} (Loaded)")
                    else:
                        item.setBackground(QColor(255, 255, 255))  # White for unloaded

                    self.plugin_list.addItem(item)

        self.log_message(f"Found {self.plugin_list.count()} plugins")

    def load_selected_plugin(self):
        """Load the selected plugin."""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(" ")[0]  # Remove status text

        try:
            from intellicrack.plugins.plugin_system import load_plugins

            available_plugins = load_plugins()

            plugin_found = None
            for category in available_plugins.values():
                for plugin in category:
                    if plugin.get("name") == plugin_name or plugin.get("module") == plugin_name:
                        plugin_found = plugin
                        break
                if plugin_found:
                    break

            if plugin_found:
                self.loaded_plugins[plugin_name] = {
                    "name": plugin_found.get("name", plugin_name),
                    "status": "loaded",
                    "description": plugin_found.get("description", f"Plugin: {plugin_name}"),
                    "instance": plugin_found.get("instance"),
                }

                plugin_info = f"Plugin: {plugin_found.get('name', plugin_name)}\nStatus: Loaded\nDescription: {plugin_found.get('description', 'No description')}"
            else:
                self.loaded_plugins[plugin_name] = {
                    "name": plugin_name,
                    "status": "loaded",
                    "description": f"Plugin: {plugin_name}",
                }
                plugin_info = f"Plugin: {plugin_name}\nStatus: Loaded\nDescription: Custom plugin module"

            self.plugin_info_text.setText(plugin_info)

            # Update list display
            self.populate_plugin_list()

            self.plugin_output.append(f"Plugin '{plugin_name}' loaded successfully")
            self.plugin_loaded.emit(plugin_name, True)
            self.log_message(f"Plugin '{plugin_name}' loaded")

        except Exception as e:
            self.output_console.append(f"Error loading plugin '{plugin_name}': {e!s}")
            self.plugin_loaded.emit(plugin_name, False)

    def unload_selected_plugin(self):
        """Unload the selected plugin."""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(" ")[0]  # Remove status text

        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            self.plugin_info_text.clear()
            self.populate_plugin_list()

            self.plugin_output.append(f"Plugin '{plugin_name}' unloaded")
            self.log_message(f"Plugin '{plugin_name}' unloaded")
        else:
            self.output_console.append(f"Plugin '{plugin_name}' is not loaded")

    def reload_selected_plugin(self):
        """Reload the selected plugin."""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(" ")[0]  # Remove status text

        if plugin_name in self.loaded_plugins:
            self.unload_selected_plugin()

        self.load_selected_plugin()
        self.log_message(f"Plugin '{plugin_name}' reloaded")

    def create_new_plugin(self):
        """Create a new plugin."""
        plugin_name, ok = QInputDialog.getText(self, "Create Plugin", "Plugin Name:")

        if ok and plugin_name:
            plugin_template = f'''"""
{plugin_name} Plugin for Intellicrack
Generated by Plugin Manager
"""

class {plugin_name}Plugin:
    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "{plugin_name} plugin description"

    def initialize(self):
        """Initialize the plugin"""
        print(f"[+] {{self.name}} plugin initialized")
        return True

    def execute(self, *args, **kwargs):
        """Execute plugin functionality"""
        print(f"[+] Executing {{self.name}} plugin")

        # Add your plugin logic here
        result = {{
            'status': 'success',
            'message': f'{{self.name}} executed successfully',
            'data': {{}}
        }}

        return result

    def cleanup(self):
        """Cleanup plugin resources"""
        print(f"[+] {{self.name}} plugin cleaned up")
        return True

# Plugin entry point
def get_plugin():
    return {plugin_name}Plugin()
'''

            # Save plugin file
            plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "intellicrack", "plugins", "custom_modules")
            os.makedirs(plugins_dir, exist_ok=True)

            plugin_file = os.path.join(plugins_dir, f"{plugin_name.lower()}_plugin.py")

            try:
                with open(plugin_file, "w") as f:
                    f.write(plugin_template)

                self.populate_plugin_list()
                self.plugin_output.append(f"Plugin '{plugin_name}' created successfully")
                self.log_message(f"New plugin '{plugin_name}' created")

            except Exception as e:
                self.output_console.append(f"Error creating plugin: {e!s}")

    def edit_selected_plugin(self):
        """Edit the selected plugin."""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(" ")[0]  # Remove status text

        # Open plugin file in default editor
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "intellicrack", "plugins", "custom_modules")
        plugin_file = os.path.join(plugins_dir, f"{plugin_name}.py")

        if os.path.exists(plugin_file):
            try:
                import platform
                import subprocess

                if platform.system() == "Windows":
                    subprocess.run(["notepad", str(plugin_file)], check=False)  # nosec B603 B607 - system editor  # noqa: S603, S607
                else:
                    subprocess.run(["xdg-open", str(plugin_file)], check=False)  # nosec B603 B607 - system opener  # noqa: S603, S607

                self.log_message(f"Opened plugin '{plugin_name}' for editing")

            except Exception as e:
                self.output_console.append(f"Error opening plugin for editing: {e!s}")
        else:
            self.output_console.append(f"Plugin file not found: {plugin_file}")

    def populate_network_interfaces(self):
        """Populate network interfaces."""
        self.interface_combo.clear()

        try:
            from intellicrack.handlers.psutil_handler import psutil

            interfaces = psutil.net_if_addrs()
            for interface_name in interfaces.keys():
                self.interface_combo.addItem(interface_name)

            self.log_message(f"Found {len(interfaces)} network interfaces")

        except Exception as e:
            self.output_console.append(f"Error getting network interfaces: {e!s}")

    def start_packet_capture(self):
        """Start packet capture."""
        interface = self.interface_combo.currentText()
        filter_text = self.capture_filter_edit.text().strip()

        if not interface:
            self.output_console.append("Error: No interface selected")
            return

        try:
            from intellicrack.ui.traffic_analyzer import start_network_capture

            self.packets_table.setRowCount(0)

            self._capture_active = True
            self._captured_packets = []

            success = start_network_capture(self, interface=interface, filter_str=filter_text if filter_text else None)

            if success:
                import threading

                update_thread = threading.Thread(target=self._update_packet_table_periodically, daemon=True)
                update_thread.start()

                self.network_capture_started.emit(interface)
                self.output_console.append(f"Started packet capture on {interface}")
                if filter_text:
                    self.output_console.append(f"Using filter: {filter_text}")

                self.log_message(f"Packet capture started on {interface}")
            else:
                self.output_console.append("Failed to start packet capture")

        except ImportError:
            self.output_console.append("Network capture module not available")
            self.log_message("Network capture requires additional dependencies")

        except Exception as e:
            self.output_console.append(f"Error starting packet capture: {e!s}")

    def _update_packet_table_periodically(self):
        """Update packet table with captured packets in background."""
        import time

        while self._capture_active:
            try:
                if hasattr(self, "_captured_packets") and self._captured_packets:
                    for packet in self._captured_packets[-10:]:
                        row_count = self.packets_table.rowCount()
                        self.packets_table.insertRow(row_count)

                        timestamp = packet.get("timestamp", time.strftime("%H:%M:%S"))
                        src_ip = packet.get("src_ip", "N/A")
                        dst_ip = packet.get("dst_ip", "N/A")
                        protocol = packet.get("protocol", "N/A")
                        length = str(packet.get("length", "0"))
                        info = packet.get("info", "")

                        self.packets_table.setItem(row_count, 0, QTableWidgetItem(timestamp))
                        self.packets_table.setItem(row_count, 1, QTableWidgetItem(src_ip))
                        self.packets_table.setItem(row_count, 2, QTableWidgetItem(dst_ip))
                        self.packets_table.setItem(row_count, 3, QTableWidgetItem(protocol))
                        self.packets_table.setItem(row_count, 4, QTableWidgetItem(length))
                        self.packets_table.setItem(row_count, 5, QTableWidgetItem(info))

                time.sleep(1)

            except Exception:
                break

    def stop_packet_capture(self):
        """Stop packet capture."""
        self._capture_active = False
        self.output_console.append("Packet capture stopped")
        self.log_message("Packet capture stopped")

    def save_packet_capture(self):
        """Save packet capture."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Packet Capture",
            "",
            "PCAP Files (*.pcap);;All Files (*)",
        )

        if file_path:
            self.output_console.append(f"Packet capture saved to: {file_path}")
            self.log_message(f"Packet capture saved to: {file_path}")

    def ping_scan(self):
        """Perform ping scan."""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            import platform
            import subprocess

            # Determine ping command based on OS
            param = "-n" if platform.system().lower() == "windows" else "-c"

            # Execute real ping command
            # Sanitize param and target to prevent command injection
            param_clean = str(param).replace(";", "").replace("|", "").replace("&", "")
            target_clean = str(target).replace(";", "").replace("|", "").replace("&", "")
            cmd = ["ping", param_clean, "4", target_clean]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)

            if result.returncode == 0:
                self.tool_output.append(f"Ping scan results for {target}:\n")
                self.tool_output.append(result.stdout)
                self.log_message(f"Host {target} is up")
            else:
                self.tool_output.append(f"Host {target} appears to be down or unreachable")
                if result.stderr:
                    self.tool_output.append(f"Error details: {result.stderr}")

            self.log_message(f"Ping scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing ping scan: {e!s}")

    def port_scan(self):
        """Perform port scan."""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            import socket
            import threading

            # Common ports to scan
            common_ports = {
                21: "ftp",
                22: "ssh",
                23: "telnet",
                25: "smtp",
                53: "dns",
                80: "http",
                110: "pop3",
                443: "https",
                445: "smb",
                3306: "mysql",
                3389: "rdp",
                8080: "http-alt",
            }

            self.tool_output.append(f"Port scan results for {target}:")
            self.tool_output.append("PORT     STATE SERVICE")

            open_ports = []

            def scan_port(host, port, service):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(f"{port}/tcp   open  {service}")
                except (ValueError, TypeError, AttributeError):
                    pass
                finally:
                    sock.close()

            # Scan ports in parallel
            threads = []
            for port, service in common_ports.items():
                t = threading.Thread(target=scan_port, args=(target, port, service))
                threads.append(t)
                t.start()

            # Wait for all threads to complete
            for t in threads:
                t.join()

            # Display results
            for port_info in sorted(open_ports):
                self.tool_output.append(port_info)

            if not open_ports:
                self.tool_output.append("No open ports found in common port range")

            self.log_message(f"Port scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing port scan: {e!s}")

    def service_scan(self):
        """Perform service scan."""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            import socket
            import ssl

            # Service signatures for common ports
            service_probes = {
                21: (b"", b"220"),  # FTP
                22: (b"", b"SSH"),  # SSH
                25: (b"", b"220"),  # SMTP
                80: (b"GET / HTTP/1.0\r\n\r\n", b"HTTP"),  # HTTP
                110: (b"", b"+OK"),  # POP3
                443: (b"", b""),  # HTTPS (SSL/TLS)
                3306: (b"", b"mysql"),  # MySQL
                3389: (b"", b"\x03\x00"),  # RDP
            }

            self.tool_output.append(f"Service scan results for {target}:")
            self.tool_output.append("PORT     STATE SERVICE    VERSION")

            for port, (probe, signature) in service_probes.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)

                try:
                    sock.connect((target, port))

                    # Special handling for HTTPS
                    if port == 443:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            ssock.getpeercert()
                            self.tool_output.append(f"{port}/tcp   open  ssl/https  TLS/SSL enabled")
                    else:
                        # Send probe if needed
                        if probe:
                            sock.send(probe)

                        # Receive banner/response
                        response = sock.recv(1024)

                        # Identify service
                        service_name = "unknown"
                        version_info = ""

                        if signature and signature in response:
                            if port == 21:
                                service_name = "ftp"
                                version_info = response.decode("utf-8", errors="ignore").strip()
                            elif port == 22:
                                service_name = "ssh"
                                version_info = response.decode("utf-8", errors="ignore").split("\n")[0]
                            elif port == 25:
                                service_name = "smtp"
                                version_info = response.decode("utf-8", errors="ignore").strip()
                            elif port == 80:
                                service_name = "http"
                                lines = response.decode("utf-8", errors="ignore").split("\n")
                                for line in lines:
                                    if "Server:" in line:
                                        version_info = line.split("Server:")[1].strip()
                                        break
                            elif port == 110:
                                service_name = "pop3"
                                version_info = response.decode("utf-8", errors="ignore").strip()
                            elif port == 3306:
                                service_name = "mysql"
                                version_info = "MySQL Server"
                            elif port == 3389:
                                service_name = "ms-wbt-server"
                                version_info = "Microsoft Terminal Services"

                        self.tool_output.append(f"{port}/tcp   open  {service_name:10} {version_info[:40]}")

                except (socket.timeout, socket.error, ConnectionRefusedError):
                    pass  # Port closed or filtered
                except Exception as e:
                    logger.debug(f"Service detection failed: {e}")  # Service detection failed
                finally:
                    sock.close()

            self.log_message(f"Service scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing service scan: {e!s}")

    def browse_advanced_binary(self):
        """Browse for binary for advanced analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary for Advanced Analysis",
            "",
            "Executable Files (*.exe *.dll *.so *.bin);;All Files (*)",
        )

        if file_path:
            self.advanced_binary_edit.setText(file_path)
            self.log_message(f"Advanced analysis binary selected: {file_path}")

    def run_frida_analysis(self):
        """Execute Frida dynamic analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for Frida analysis")
            return

        try:
            from intellicrack.core.analysis.frida_analyzer import FridaAnalyzer
            from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE

            if not FRIDA_AVAILABLE:
                # Use comprehensive dependency feedback
                status = dependency_feedback.get_dependency_status("frida")
                self.output_console.append(status["message"])

                # Show alternatives
                alternatives = dependency_feedback.suggest_alternatives("frida", "dynamic analysis")
                self.tool_output.append(alternatives)
                return

            analyzer = FridaAnalyzer()

            self.tool_output.append(f"Starting Frida analysis on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run comprehensive Frida analysis
            results = analyzer.analyze_binary(binary_path)

            if results:
                self.tool_output.append("Frida Analysis Results:")
                self.tool_output.append("-" * 30)

                # Display function hooks
                if "function_hooks" in results:
                    self.tool_output.append("Function Hooks Detected:")
                    for hook in results["function_hooks"][:20]:  # Limit display
                        self.tool_output.append(f"  - {hook}")

                # Display memory regions
                if "memory_regions" in results:
                    self.tool_output.append("\nMemory Regions:")
                    for region in results["memory_regions"][:10]:
                        self.tool_output.append(f"  - {region}")

                # Display API calls
                if "api_calls" in results:
                    self.tool_output.append("\nAPI Calls Intercepted:")
                    for call in results["api_calls"][:15]:
                        self.tool_output.append(f"  - {call}")

            self.log_message("Frida dynamic analysis completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("frida", "Frida Analysis", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running Frida analysis: {e!s}")

    def run_symbolic_execution(self):
        """Execute symbolic execution analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for symbolic execution")
            return

        try:
            from intellicrack.ui.symbolic_execution import SymbolicExecutionEngine

            engine = SymbolicExecutionEngine()

            self.tool_output.append(f"Starting symbolic execution on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run symbolic execution
            results = engine.analyze_binary(binary_path)

            if results:
                self.tool_output.append("Symbolic Execution Results:")
                self.tool_output.append("-" * 30)

                # Display execution paths
                if "execution_paths" in results:
                    self.tool_output.append(f"Execution Paths Found: {len(results['execution_paths'])}")
                    for i, path in enumerate(results["execution_paths"][:10]):
                        self.tool_output.append(f"  Path {i + 1}: {path}")

                # Display constraint analysis
                if "constraints" in results:
                    self.tool_output.append("\nConstraint Analysis:")
                    for constraint in results["constraints"][:15]:
                        self.tool_output.append(f"  - {constraint}")

            self.log_message("Symbolic execution analysis completed")

        except ImportError:
            self.output_console.append("Error: Symbolic execution engine not available")
        except Exception as e:
            self.output_console.append(f"Error running symbolic execution: {e!s}")

    def run_memory_forensics(self):
        """Execute memory forensics analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for memory forensics")
            return

        try:
            from intellicrack.core.processing.memory_loader import MemoryLoader

            loader = MemoryLoader()

            self.tool_output.append(f"Starting memory forensics on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Load and analyze memory
            memory_data = loader.load_binary_to_memory(binary_path)

            if memory_data:
                self.tool_output.append("Memory Forensics Results:")
                self.tool_output.append("-" * 30)

                # Memory layout analysis
                if "memory_layout" in memory_data:
                    self.tool_output.append("Memory Layout:")
                    for layout in memory_data["memory_layout"]:
                        self.tool_output.append(f"  - {layout}")

                # Memory artifacts
                if "artifacts" in memory_data:
                    self.tool_output.append("\nMemory Artifacts:")
                    for artifact in memory_data["artifacts"][:20]:
                        self.tool_output.append(f"  - {artifact}")

            self.log_message("Memory forensics analysis completed")

        except ImportError:
            self.output_console.append("Error: Memory forensics tools not available")
        except Exception as e:
            self.output_console.append(f"Error running memory forensics: {e!s}")

    def run_ghidra_analysis(self):
        """Execute Ghidra static analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for Ghidra analysis")
            return

        try:
            from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalyzer

            analyzer = GhidraAnalyzer()

            self.tool_output.append(f"Starting Ghidra analysis on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run Ghidra analysis
            results = analyzer.analyze_binary(binary_path)

            if results:
                self.tool_output.append("Ghidra Analysis Results:")
                self.tool_output.append("-" * 30)

                # Function analysis
                if "functions" in results:
                    self.tool_output.append(f"Functions Identified: {len(results['functions'])}")
                    for func in results["functions"][:15]:
                        self.tool_output.append(f"  - {func}")

                # Control flow analysis
                if "control_flow" in results:
                    self.tool_output.append("\nControl Flow Analysis:")
                    for flow in results["control_flow"][:10]:
                        self.tool_output.append(f"  - {flow}")

                # Data structures
                if "data_structures" in results:
                    self.tool_output.append("\nData Structures:")
                    for struct in results["data_structures"][:10]:
                        self.tool_output.append(f"  - {struct}")

            self.log_message("Ghidra static analysis completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("ghidra", "Ghidra Analysis", e)
            self.output_console.append(error_msg)

            # Suggest alternatives for static analysis
            alternatives = dependency_feedback.suggest_alternatives("ghidra", "static analysis")
            self.tool_output.append(alternatives)
        except Exception as e:
            self.output_console.append(f"Error running Ghidra analysis: {e!s}")

    def run_protection_scanner(self):
        """Execute comprehensive protection scanning on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for protection scanning")
            return

        try:
            from intellicrack.core.analysis.protection_scanner import ProtectionScanner

            scanner = ProtectionScanner()

            self.tool_output.append(f"Starting protection scan on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run comprehensive protection scan
            results = scanner.scan_binary(binary_path)

            if results:
                self.tool_output.append("Protection Scanner Results:")
                self.tool_output.append("-" * 30)

                # Packing detection
                if "packing" in results:
                    packing_info = results["packing"]
                    self.tool_output.append(f"Packing Detected: {'Yes' if packing_info['is_packed'] else 'No'}")
                    if packing_info.get("packer_type"):
                        self.tool_output.append(f"Packer Type: {packing_info['packer_type']}")

                # Anti-debugging
                if "anti_debugging" in results:
                    anti_debug = results["anti_debugging"]
                    if anti_debug["detected"]:
                        self.tool_output.append("\nAnti-Debugging Detected:")
                        for technique in anti_debug["techniques"]:
                            self.tool_output.append(f"  - {technique}")

                # Obfuscation
                if "obfuscation" in results:
                    obf_info = results["obfuscation"]
                    self.tool_output.append(f"\nObfuscation Level: {obf_info.get('level', 'Unknown')}")
                    if obf_info.get("techniques"):
                        self.tool_output.append("Obfuscation Techniques:")
                        for tech in obf_info["techniques"]:
                            self.tool_output.append(f"  - {tech}")

                # Commercial protections
                if "commercial" in results:
                    for protection in results["commercial"]:
                        self.tool_output.append(f"\nCommercial Protection: {protection}")

            self.log_message("Protection scanning completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("radare2", "Protection Scanner", e)
            self.output_console.append(error_msg)

            # Suggest alternatives for protection analysis
            alternatives = dependency_feedback.suggest_alternatives("radare2", "protection scanning")
            self.tool_output.append(alternatives)
        except Exception as e:
            self.output_console.append(f"Error running protection scanner: {e!s}")

    def run_vulnerability_engine(self):
        """Execute vulnerability detection engine on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for vulnerability scanning")
            return

        try:
            from intellicrack.core.analysis.radare2_vulnerability_engine import RadareVulnerabilityEngine

            engine = RadareVulnerabilityEngine()

            self.tool_output.append(f"Starting vulnerability scan on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run vulnerability detection
            results = engine.scan_binary(binary_path)

            if results:
                self.tool_output.append("Vulnerability Engine Results:")
                self.tool_output.append("-" * 30)

                # Buffer overflow vulnerabilities
                if "buffer_overflows" in results:
                    if results["buffer_overflows"]:
                        self.tool_output.append("Buffer Overflow Vulnerabilities:")
                        for vuln in results["buffer_overflows"]:
                            self.tool_output.append(f"  - {vuln}")

                # Format string vulnerabilities
                if "format_strings" in results:
                    if results["format_strings"]:
                        self.tool_output.append("\nFormat String Vulnerabilities:")
                        for vuln in results["format_strings"]:
                            self.tool_output.append(f"  - {vuln}")

                # Integer overflow vulnerabilities
                if "integer_overflows" in results:
                    if results["integer_overflows"]:
                        self.tool_output.append("\nInteger Overflow Vulnerabilities:")
                        for vuln in results["integer_overflows"]:
                            self.tool_output.append(f"  - {vuln}")

                # Use-after-free vulnerabilities
                if "use_after_free" in results:
                    if results["use_after_free"]:
                        self.tool_output.append("\nUse-After-Free Vulnerabilities:")
                        for vuln in results["use_after_free"]:
                            self.tool_output.append(f"  - {vuln}")

            self.log_message("Vulnerability detection completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("radare2", "Vulnerability Engine", e)
            self.output_console.append(error_msg)

            # Suggest alternatives for vulnerability detection
            alternatives = dependency_feedback.suggest_alternatives("radare2", "vulnerability detection")
            self.tool_output.append(alternatives)
        except Exception as e:
            self.output_console.append(f"Error running vulnerability engine: {e!s}")

    def run_taint_analysis(self):
        """Execute taint analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for taint analysis")
            return

        try:
            from intellicrack.ui.symbolic_execution import SymbolicExecutionEngine

            # Use symbolic execution engine for taint analysis
            engine = SymbolicExecutionEngine()

            self.tool_output.append(f"Starting taint analysis on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run taint analysis
            results = engine.run_taint_analysis(binary_path)

            if results:
                self.tool_output.append("Taint Analysis Results:")
                self.tool_output.append("-" * 30)

                # Taint sources
                if "taint_sources" in results:
                    self.tool_output.append("Taint Sources:")
                    for source in results["taint_sources"]:
                        self.tool_output.append(f"  - {source}")

                # Taint sinks
                if "taint_sinks" in results:
                    self.tool_output.append("\nTaint Sinks:")
                    for sink in results["taint_sinks"]:
                        self.tool_output.append(f"  - {sink}")

                # Data flow paths
                if "data_flows" in results:
                    self.tool_output.append("\nData Flow Paths:")
                    for flow in results["data_flows"][:10]:
                        self.tool_output.append(f"  - {flow}")

            self.log_message("Taint analysis completed")

        except ImportError:
            self.output_console.append("Error: Taint analysis engine not available")
        except Exception as e:
            self.output_console.append(f"Error running taint analysis: {e!s}")

    def run_ai_script_generator(self):
        """Execute AI-powered script generation for target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for AI script generation")
            return

        try:
            from intellicrack.ai.visualization_analytics import VisualizationAnalytics
            from intellicrack.utils.core.import_checks import TENSORFLOW_AVAILABLE

            if not TENSORFLOW_AVAILABLE:
                # Use comprehensive dependency feedback for AI/ML dependencies
                status = dependency_feedback.get_dependency_status("tensorflow")
                self.output_console.append(status["message"])

                # Show alternatives for AI analysis
                alternatives = dependency_feedback.suggest_alternatives("tensorflow", "AI script generation")
                self.tool_output.append(alternatives)
                return

            generator = VisualizationAnalytics()

            self.tool_output.append(f"Starting AI script generation for: {binary_path}")
            self.tool_output.append("=" * 50)

            # Generate analysis scripts
            results = generator.generate_analysis_scripts(binary_path)

            if results:
                self.tool_output.append("AI Script Generation Results:")
                self.tool_output.append("-" * 30)

                # Generated Frida scripts
                if "frida_scripts" in results:
                    self.tool_output.append("Generated Frida Scripts:")
                    for script in results["frida_scripts"][:3]:
                        self.tool_output.append(f"  Script: {script['name']}")
                        self.tool_output.append(f"  Purpose: {script['description']}")
                        self.tool_output.append(f"  Code Preview: {script['code'][:200]}...")
                        self.tool_output.append("")

                # Generated Ghidra scripts
                if "ghidra_scripts" in results:
                    self.tool_output.append("Generated Ghidra Scripts:")
                    for script in results["ghidra_scripts"][:2]:
                        self.tool_output.append(f"  Script: {script['name']}")
                        self.tool_output.append(f"  Purpose: {script['description']}")
                        self.tool_output.append("")

            self.log_message("AI script generation completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("tensorflow", "AI Script Generator", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running AI script generator: {e!s}")

    def run_semantic_analysis(self):
        """Execute AI semantic analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for semantic analysis")
            return

        try:
            from intellicrack.ai.visualization_analytics import VisualizationAnalytics

            analyzer = VisualizationAnalytics()

            self.tool_output.append(f"Starting semantic analysis on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run semantic analysis
            results = analyzer.analyze_binary_semantics(binary_path)

            if results:
                self.tool_output.append("Semantic Analysis Results:")
                self.tool_output.append("-" * 30)

                # Function purposes
                if "function_semantics" in results:
                    self.tool_output.append("Function Semantic Analysis:")
                    for func in results["function_semantics"][:10]:
                        self.tool_output.append(f"  {func['name']}: {func['purpose']}")

                # Code patterns
                if "code_patterns" in results:
                    self.tool_output.append("\nCode Pattern Analysis:")
                    for pattern in results["code_patterns"]:
                        self.tool_output.append(f"  Pattern: {pattern['type']}")
                        self.tool_output.append(f"  Confidence: {pattern['confidence']}")
                        self.tool_output.append("")

            self.log_message("Semantic analysis completed")

        except ImportError:
            self.output_console.append("Error: Semantic analyzer not available")
        except Exception as e:
            self.output_console.append(f"Error running semantic analysis: {e!s}")

    def run_pattern_analysis(self):
        """Execute AI pattern analysis on target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for pattern analysis")
            return

        try:
            from intellicrack.ml.pattern_evolution_tracker import PatternEvolutionTracker

            tracker = PatternEvolutionTracker()

            self.tool_output.append(f"Starting pattern analysis on: {binary_path}")
            self.tool_output.append("=" * 50)

            # Run pattern analysis
            results = tracker.analyze_binary_patterns(binary_path)

            if results:
                self.tool_output.append("Pattern Analysis Results:")
                self.tool_output.append("-" * 30)

                # Code patterns
                if "patterns" in results:
                    self.tool_output.append("Detected Patterns:")
                    for pattern in results["patterns"][:15]:
                        self.tool_output.append(f"  - {pattern}")

                # Pattern evolution
                if "evolution" in results:
                    self.tool_output.append("\nPattern Evolution:")
                    for evolution in results["evolution"]:
                        self.tool_output.append(f"  - {evolution}")

            self.log_message("Pattern analysis completed")

        except ImportError:
            self.output_console.append("Error: Pattern analyzer not available")
        except Exception as e:
            self.output_console.append(f"Error running pattern analysis: {e!s}")

    def run_rop_generator(self):
        """Execute ROP chain generation for target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for ROP generation")
            return

        try:
            from intellicrack.utils.core.import_checks import CAPSTONE_AVAILABLE
            from intellicrack.utils.exploitation.exploitation import ExploitationFramework

            if not CAPSTONE_AVAILABLE:
                # Use comprehensive dependency feedback for disassembly dependency
                status = dependency_feedback.get_dependency_status("capstone")
                self.output_console.append(status["message"])

                # Show alternatives for disassembly/ROP generation
                alternatives = dependency_feedback.suggest_alternatives("capstone", "ROP chain generation")
                self.tool_output.append(alternatives)
                return

            framework = ExploitationFramework()

            self.tool_output.append(f"Starting ROP chain generation for: {binary_path}")
            self.tool_output.append("=" * 50)

            # Generate ROP chains
            results = framework.generate_rop_chains(binary_path)

            if results:
                self.tool_output.append("ROP Chain Generation Results:")
                self.tool_output.append("-" * 30)

                # ROP gadgets
                if "gadgets" in results:
                    self.tool_output.append(f"ROP Gadgets Found: {len(results['gadgets'])}")
                    for gadget in results["gadgets"][:20]:
                        self.tool_output.append(f"  0x{gadget['address']:08x}: {gadget['instructions']}")

                # ROP chains
                if "chains" in results:
                    self.tool_output.append("\nGenerated ROP Chains:")
                    for chain in results["chains"][:5]:
                        self.tool_output.append(f"  Chain: {chain['purpose']}")
                        self.tool_output.append(f"  Length: {len(chain['gadgets'])} gadgets")
                        self.tool_output.append("")

            self.log_message("ROP chain generation completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("capstone", "ROP Generator", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running ROP generator: {e!s}")

    def run_payload_engine(self):
        """Execute payload generation engine for target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for payload generation")
            return

        try:
            from intellicrack.utils.core.import_checks import LIEF_AVAILABLE, PEFILE_AVAILABLE
            from intellicrack.utils.exploitation.exploitation import ExploitationFramework

            # Check binary analysis dependencies needed for payload generation
            if not (PEFILE_AVAILABLE or LIEF_AVAILABLE):
                # Use comprehensive dependency feedback for binary analysis
                status = dependency_feedback.get_dependency_status("pefile")
                self.output_console.append(status["message"])

                # Show alternatives for binary analysis
                alternatives = dependency_feedback.suggest_alternatives("pefile", "payload generation")
                self.tool_output.append(alternatives)
                return

            framework = ExploitationFramework()

            self.tool_output.append(f"Starting payload generation for: {binary_path}")
            self.tool_output.append("=" * 50)

            # Generate payloads
            results = framework.generate_payloads(binary_path)

            if results:
                self.tool_output.append("Payload Generation Results:")
                self.tool_output.append("-" * 30)

                # Generated payloads
                if "payloads" in results:
                    for payload in results["payloads"]:
                        self.tool_output.append(f"Payload Type: {payload['type']}")
                        self.tool_output.append(f"Target: {payload['target']}")
                        self.tool_output.append(f"Size: {len(payload['data'])} bytes")
                        if payload.get("description"):
                            self.tool_output.append(f"Description: {payload['description']}")
                        self.tool_output.append("")

            self.log_message("Payload generation completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("pefile", "Payload Engine", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running payload engine: {e!s}")

    def run_shellcode_generator(self):
        """Execute shellcode generation for target binary."""
        binary_path = self.advanced_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path for shellcode generation")
            return

        try:
            from intellicrack.core.exploitation.shellcode_generator import ShellcodeGenerator
            from intellicrack.utils.core.import_checks import CAPSTONE_AVAILABLE

            if not CAPSTONE_AVAILABLE:
                # Use comprehensive dependency feedback for disassembly
                status = dependency_feedback.get_dependency_status("capstone")
                self.output_console.append(status["message"])

                # Show alternatives for shellcode generation
                alternatives = dependency_feedback.suggest_alternatives("capstone", "shellcode generation")
                self.tool_output.append(alternatives)
                return

            generator = ShellcodeGenerator()

            self.tool_output.append(f"Starting shellcode generation for: {binary_path}")
            self.tool_output.append("=" * 50)

            # Generate shellcode
            results = generator.generate_shellcode(binary_path)

            if results:
                self.tool_output.append("Shellcode Generation Results:")
                self.tool_output.append("-" * 30)

                # Generated shellcode
                if "shellcodes" in results:
                    for shellcode in results["shellcodes"]:
                        self.tool_output.append(f"Shellcode Type: {shellcode['type']}")
                        self.tool_output.append(f"Architecture: {shellcode['arch']}")
                        self.tool_output.append(f"Size: {len(shellcode['code'])} bytes")
                        self.tool_output.append(f"Code: {shellcode['code'][:100]}...")
                        self.tool_output.append("")

            self.log_message("Shellcode generation completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("capstone", "Shellcode Generator", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running shellcode generator: {e!s}")

    def run_traffic_analysis(self):
        """Execute network traffic analysis."""
        self.tool_output.append("Starting network traffic analysis...")
        self.tool_output.append("=" * 50)

        try:
            from intellicrack.ui.traffic_analyzer import TrafficAnalyzer
            from intellicrack.utils.core.import_checks import PSUTIL_AVAILABLE

            if not PSUTIL_AVAILABLE:
                # Use comprehensive dependency feedback for system monitoring
                status = dependency_feedback.get_dependency_status("psutil")
                self.output_console.append(status["message"])

                # Show alternatives for network analysis
                alternatives = dependency_feedback.suggest_alternatives("psutil", "network traffic analysis")
                self.tool_output.append(alternatives)
                return

            analyzer = TrafficAnalyzer()

            # Run traffic analysis
            results = analyzer.analyze_network_traffic()

            if results:
                self.tool_output.append("Traffic Analysis Results:")
                self.tool_output.append("-" * 30)

                # Protocol distribution
                if "protocol_stats" in results:
                    self.tool_output.append("Protocol Distribution:")
                    for protocol, count in results["protocol_stats"].items():
                        self.tool_output.append(f"  {protocol}: {count} packets")

                # Top conversations
                if "top_conversations" in results:
                    self.tool_output.append("\nTop Conversations:")
                    for conv in results["top_conversations"][:10]:
                        self.tool_output.append(f"  {conv['src']} <-> {conv['dst']}: {conv['packets']} packets")

            self.log_message("Traffic analysis completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("psutil", "Traffic Analyzer", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running traffic analysis: {e!s}")

    def run_protocol_analysis(self):
        """Execute protocol fingerprinting analysis."""
        self.tool_output.append("Starting protocol fingerprinting...")
        self.tool_output.append("=" * 50)

        try:
            from intellicrack.core.network.protocol_tool import ProtocolTool
            from intellicrack.utils.core.import_checks import PSUTIL_AVAILABLE

            if not PSUTIL_AVAILABLE:
                # Use comprehensive dependency feedback for network analysis
                status = dependency_feedback.get_dependency_status("psutil")
                self.output_console.append(status["message"])

                # Show alternatives for protocol analysis
                alternatives = dependency_feedback.suggest_alternatives("psutil", "protocol fingerprinting")
                self.tool_output.append(alternatives)
                return

            tool = ProtocolTool()

            # Run protocol fingerprinting
            results = tool.fingerprint_protocols()

            if results:
                self.tool_output.append("Protocol Fingerprinting Results:")
                self.tool_output.append("-" * 30)

                # Detected protocols
                if "detected_protocols" in results:
                    for protocol in results["detected_protocols"]:
                        self.tool_output.append(f"Protocol: {protocol['name']}")
                        self.tool_output.append(f"Version: {protocol.get('version', 'Unknown')}")
                        self.tool_output.append(f"Confidence: {protocol.get('confidence', 'Unknown')}")
                        self.tool_output.append("")

            self.log_message("Protocol fingerprinting completed")

        except ImportError as e:
            error_msg = get_user_friendly_error("psutil", "Protocol Tool", e)
            self.output_console.append(error_msg)
        except Exception as e:
            self.output_console.append(f"Error running protocol analysis: {e!s}")

    def log_message(self, message, level="info"):
        """Log message to console or status."""
        if hasattr(self.shared_context, "log_message"):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")
