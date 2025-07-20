"""Tools tab for Intellicrack.

This module provides the tools interface for plugin management,
custom tool integration, and external tool execution.
"""
import os
import subprocess

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
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
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .base_tab import BaseTab


class ToolsTab(BaseTab):
    """Tools tab consolidating tools, plugins, and network analysis"""

    tool_executed = pyqtSignal(str, str)
    plugin_loaded = pyqtSignal(str, bool)
    network_capture_started = pyqtSignal(str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize tools tab with external tool integration and management."""
        super().__init__(shared_context, parent)
        self.available_tools = {}
        self.loaded_plugins = {}
        self.network_interfaces = []

    def setup_content(self):
        """Setup the tools tab content"""
        layout = QHBoxLayout(self)

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

        layout.addWidget(splitter)
        self.is_loaded = True

    def create_tools_panel(self):
        """Create the tools control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Tools tabs
        self.tools_tabs = QTabWidget()
        self.tools_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Add tool categories
        self.tools_tabs.addTab(self.create_system_tools_tab(), "System Tools")
        self.tools_tabs.addTab(self.create_analysis_tools_tab(), "Analysis Tools")
        self.tools_tabs.addTab(self.create_plugin_manager_tab(), "Plugin Manager")
        self.tools_tabs.addTab(self.create_network_tools_tab(), "Network Tools")

        layout.addWidget(self.tools_tabs)
        return panel

    def create_system_tools_tab(self):
        """Create system tools tab"""
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

        file_info_btn = QPushButton("File Info")
        file_info_btn.clicked.connect(self.get_file_info)

        hex_dump_btn = QPushButton("Hex Dump")
        hex_dump_btn.clicked.connect(self.create_hex_dump)

        strings_btn = QPushButton("Extract Strings")
        strings_btn.clicked.connect(self.extract_strings)

        file_ops_layout.addWidget(file_info_btn)
        file_ops_layout.addWidget(hex_dump_btn)
        file_ops_layout.addWidget(strings_btn)

        file_layout.addLayout(file_path_layout)
        file_layout.addLayout(file_ops_layout)

        # Registry Tools (Windows)
        registry_group = QGroupBox("Registry Tools")
        registry_layout = QVBoxLayout(registry_group)

        reg_query_layout = QHBoxLayout()
        reg_query_layout.addWidget(QLabel("Registry Key:"))
        self.reg_key_edit = QLineEdit()
        self.reg_key_edit.setPlaceholderText("HKEY_LOCAL_MACHINE\\SOFTWARE\\...")
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
        """Create analysis tools tab"""
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
        """Create plugin manager tab"""
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
        """Create network tools tab"""
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
        self.capture_filter_edit.setPlaceholderText("e.g., tcp port 80, host 192.168.1.1")
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
        self.scan_target_edit.setPlaceholderText("IP address or range (e.g., 192.168.1.1/24)")
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

    def create_results_panel(self):
        """Create the results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFont(QFont("Consolas", 10))
        self.output_console.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")

        # Tool output viewer
        self.tool_output = QTextEdit()
        self.tool_output.setReadOnly(True)
        self.tool_output.setFont(QFont("Consolas", 10))

        # Network packets table
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(6)
        self.packets_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
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


    def get_system_info(self):
        """Get system information"""
        try:
            import platform

            import psutil

            info = []
            info.append(f"System: {platform.system()}")
            info.append(f"Release: {platform.release()}")
            info.append(f"Version: {platform.version()}")
            info.append(f"Machine: {platform.machine()}")
            info.append(f"Processor: {platform.processor()}")
            info.append(f"CPU Cores: {psutil.cpu_count()}")
            info.append(f"Memory: {psutil.virtual_memory().total // (1024**3)} GB")

            self.output_console.append("\n".join(info))
            self.log_message("System information retrieved")

        except Exception as e:
            self.output_console.append(f"Error getting system info: {str(e)}")

    def list_processes(self):
        """List running processes"""
        try:
            import psutil

            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    processes.append(f"PID: {proc_info['pid']:>6} | "
                                   f"Name: {proc_info['name']:<20} | "
                                   f"CPU: {proc_info['cpu_percent']:>5.1f}% | "
                                   f"Memory: {proc_info['memory_percent']:>5.1f}%")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            self.output_console.append("Running Processes:")
            self.output_console.append("-" * 60)
            for proc in processes[:50]:  # Limit to first 50 processes
                self.output_console.append(proc)

            self.log_message(f"Listed {len(processes)} running processes")

        except Exception as e:
            self.output_console.append(f"Error listing processes: {str(e)}")

    def get_memory_info(self):
        """Get memory information"""
        try:
            import psutil

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
            self.output_console.append(f"Error getting memory info: {str(e)}")

    def browse_file(self):
        """Browse for file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Analysis",
            "",
            "All Files (*)"
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self.log_message(f"File selected: {file_path}")

    def get_file_info(self):
        """Get file information"""
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
            self.output_console.append(f"Error getting file info: {str(e)}")

    def create_hex_dump(self):
        """Create hex dump of file"""
        file_path = self.file_path_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            self.output_console.append("Error: Invalid file path")
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB

            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_lines.append(f"{i:08x}: {hex_part:<48} |{ascii_part}|")

            self.tool_output.append("Hex Dump (first 1KB):")
            self.tool_output.append("\n".join(hex_lines))
            self.log_message("Hex dump created")

        except Exception as e:
            self.output_console.append(f"Error creating hex dump: {str(e)}")

    def extract_strings(self):
        """Extract strings from file"""
        file_path = self.file_path_edit.text().strip()
        if not file_path or not os.path.exists(file_path):
            self.output_console.append("Error: Invalid file path")
            return

        try:
            import re

            with open(file_path, 'rb') as f:
                data = f.read()

            # Extract ASCII strings (minimum length 4)
            ascii_strings = re.findall(b'[!-~]{4,}', data)
            unicode_strings = re.findall(b'(?:[!-~]\x00){4,}', data)

            self.tool_output.append("Extracted Strings:")
            self.tool_output.append("-" * 40)

            self.tool_output.append("ASCII Strings:")
            for s in ascii_strings[:100]:  # Limit to first 100
                try:
                    self.tool_output.append(s.decode('ascii'))
                except:
                    continue

            if unicode_strings:
                self.tool_output.append("\nUnicode Strings:")
                for s in unicode_strings[:50]:  # Limit to first 50
                    try:
                        decoded = s.decode('utf-16le')
                        self.tool_output.append(decoded)
                    except:
                        continue

            self.log_message(f"Extracted {len(ascii_strings)} ASCII and {len(unicode_strings)} Unicode strings")

        except Exception as e:
            self.output_console.append(f"Error extracting strings: {str(e)}")

    def query_registry(self):
        """Query Windows registry"""
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
                except WindowsError:
                    pass

                self.tool_output.append(f"Registry Key: {reg_key}")
                self.tool_output.append("-" * 40)
                for value in values:
                    self.tool_output.append(value)

                self.log_message(f"Queried registry key: {reg_key}")

        except Exception as e:
            self.output_console.append(f"Error querying registry: {str(e)}")

    def browse_analysis_binary(self):
        """Browse for binary to analyze"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary for Analysis",
            "",
            "Executable Files (*.exe *.dll *.so);;All Files (*)"
        )

        if file_path:
            self.analysis_binary_edit.setText(file_path)
            self.log_message(f"Analysis binary selected: {file_path}")

    def disassemble_binary(self):
        """Disassemble binary using external tools"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            # Try using objdump first
            result = subprocess.run(
                ['objdump', '-d', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.tool_output.append("Disassembly Output:")
                self.tool_output.append("-" * 40)
                lines = result.stdout.split('\n')[:200]  # Limit output
                self.tool_output.append('\n'.join(lines))
                self.log_message("Binary disassembled successfully")
            else:
                self.output_console.append(f"Disassembly failed: {result.stderr}")

        except FileNotFoundError:
            self.output_console.append("Error: objdump not found. Please install binutils.")
        except subprocess.TimeoutExpired:
            self.output_console.append("Error: Disassembly timed out")
        except Exception as e:
            self.output_console.append(f"Error disassembling binary: {str(e)}")

    def analyze_entropy(self):
        """Analyze binary entropy"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            import math
            from collections import Counter

            with open(binary_path, 'rb') as f:
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
                chunk = data[i:i+chunk_size]
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
                self.tool_output.append(f"  Section {i+1}: {ent:.4f}")

            # Interpretation
            if entropy > 7.5:
                self.tool_output.append("\nInterpretation: HIGH entropy - likely packed/encrypted")
            elif entropy > 6.5:
                self.tool_output.append("\nInterpretation: MEDIUM entropy - possibly compressed")
            else:
                self.tool_output.append("\nInterpretation: LOW entropy - likely not packed")

            self.log_message("Entropy analysis completed")

        except Exception as e:
            self.output_console.append(f"Error analyzing entropy: {str(e)}")

    def analyze_imports(self):
        """Analyze binary imports"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Import Analysis:")
            self.tool_output.append("-" * 40)

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    self.tool_output.append(f"\nDLL: {dll_name}")

                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8')
                            self.tool_output.append(f"  - {func_name}")
                        else:
                            self.tool_output.append(f"  - Ordinal: {imp.ordinal}")
            else:
                self.tool_output.append("No imports found")

            self.log_message("Import analysis completed")

        except ImportError:
            self.output_console.append("Error: pefile module not available")
        except Exception as e:
            self.output_console.append(f"Error analyzing imports: {str(e)}")

    def analyze_exports(self):
        """Analyze binary exports"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Export Analysis:")
            self.tool_output.append("-" * 40)

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                export_dir = pe.DIRECTORY_ENTRY_EXPORT
                self.tool_output.append(f"Export DLL Name: {export_dir.name.decode('utf-8')}")
                self.tool_output.append(f"Number of Functions: {export_dir.struct.NumberOfFunctions}")
                self.tool_output.append(f"Number of Names: {export_dir.struct.NumberOfNames}")
                self.tool_output.append("\nExported Functions:")

                for exp in export_dir.symbols:
                    if exp.name:
                        func_name = exp.name.decode('utf-8')
                        self.tool_output.append(f"  {exp.ordinal}: {func_name} (RVA: 0x{exp.address:08x})")
                    else:
                        self.tool_output.append(f"  {exp.ordinal}: <no name> (RVA: 0x{exp.address:08x})")
            else:
                self.tool_output.append("No exports found")

            self.log_message("Export analysis completed")

        except ImportError:
            self.output_console.append("Error: pefile module not available")
        except Exception as e:
            self.output_console.append(f"Error analyzing exports: {str(e)}")

    def analyze_sections(self):
        """Analyze binary sections"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            import pefile

            pe = pefile.PE(binary_path)

            self.tool_output.append("Section Analysis:")
            self.tool_output.append("-" * 60)
            self.tool_output.append(f"{'Name':<8} {'VirtAddr':<10} {'VirtSize':<10} {'RawAddr':<10} {'RawSize':<10} {'Characteristics'}")
            self.tool_output.append("-" * 60)

            for section in pe.sections:
                name = section.Name.decode('utf-8').rstrip('\x00')
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
            self.output_console.append(f"Error analyzing sections: {str(e)}")

    def analyze_symbols(self):
        """Analyze binary symbols"""
        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            self.output_console.append("Error: Invalid binary path")
            return

        try:
            # Try using nm tool
            result = subprocess.run(
                ['nm', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.tool_output.append("Symbol Analysis:")
                self.tool_output.append("-" * 40)
                lines = result.stdout.split('\n')[:200]  # Limit output
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
            self.output_console.append(f"Error analyzing symbols: {str(e)}")

    def calculate_hash(self, algorithm):
        """Calculate hash of input data"""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import hashlib

            data_bytes = data.encode('utf-8')

            if algorithm == "md5":
                hash_obj = hashlib.md5(data_bytes)
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256(data_bytes)
            else:
                self.output_console.append(f"Error: Unsupported hash algorithm: {algorithm}")
                return

            hash_value = hash_obj.hexdigest()
            self.tool_output.append(f"{algorithm.upper()} Hash: {hash_value}")
            self.log_message(f"{algorithm.upper()} hash calculated")

        except Exception as e:
            self.output_console.append(f"Error calculating hash: {str(e)}")

    def base64_encode(self):
        """Base64 encode input data"""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import base64

            data_bytes = data.encode('utf-8')
            encoded = base64.b64encode(data_bytes).decode('utf-8')

            self.tool_output.append(f"Base64 Encoded: {encoded}")
            self.log_message("Base64 encoding completed")

        except Exception as e:
            self.output_console.append(f"Error encoding data: {str(e)}")

    def base64_decode(self):
        """Base64 decode input data"""
        data = self.crypto_input.toPlainText().strip()
        if not data:
            self.output_console.append("Error: No input data provided")
            return

        try:
            import base64

            decoded_bytes = base64.b64decode(data)
            decoded = decoded_bytes.decode('utf-8')

            self.tool_output.append(f"Base64 Decoded: {decoded}")
            self.log_message("Base64 decoding completed")

        except Exception as e:
            self.output_console.append(f"Error decoding data: {str(e)}")

    def populate_plugin_list(self):
        """Populate the plugin list"""
        self.plugin_list.clear()

        # Look for plugins in the plugins directory
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "intellicrack", "plugins", "custom_modules")

        if os.path.exists(plugins_dir):
            for file in os.listdir(plugins_dir):
                if file.endswith('.py') and not file.startswith('__'):
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
        """Load the selected plugin"""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(' ')[0]  # Remove status text

        try:
            # Simulate plugin loading
            self.loaded_plugins[plugin_name] = {
                'name': plugin_name,
                'status': 'loaded',
                'description': f'Plugin: {plugin_name}'
            }

            # Update plugin info
            self.plugin_info_text.setText(f"Plugin: {plugin_name}\nStatus: Loaded\nDescription: Custom plugin module")

            # Update list display
            self.populate_plugin_list()

            self.plugin_output.append(f"Plugin '{plugin_name}' loaded successfully")
            self.plugin_loaded.emit(plugin_name, True)
            self.log_message(f"Plugin '{plugin_name}' loaded")

        except Exception as e:
            self.output_console.append(f"Error loading plugin '{plugin_name}': {str(e)}")
            self.plugin_loaded.emit(plugin_name, False)

    def unload_selected_plugin(self):
        """Unload the selected plugin"""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(' ')[0]  # Remove status text

        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            self.plugin_info_text.clear()
            self.populate_plugin_list()

            self.plugin_output.append(f"Plugin '{plugin_name}' unloaded")
            self.log_message(f"Plugin '{plugin_name}' unloaded")
        else:
            self.output_console.append(f"Plugin '{plugin_name}' is not loaded")

    def reload_selected_plugin(self):
        """Reload the selected plugin"""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(' ')[0]  # Remove status text

        if plugin_name in self.loaded_plugins:
            self.unload_selected_plugin()

        self.load_selected_plugin()
        self.log_message(f"Plugin '{plugin_name}' reloaded")

    def create_new_plugin(self):
        """Create a new plugin"""
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
                with open(plugin_file, 'w') as f:
                    f.write(plugin_template)

                self.populate_plugin_list()
                self.plugin_output.append(f"Plugin '{plugin_name}' created successfully")
                self.log_message(f"New plugin '{plugin_name}' created")

            except Exception as e:
                self.output_console.append(f"Error creating plugin: {str(e)}")

    def edit_selected_plugin(self):
        """Edit the selected plugin"""
        current_item = self.plugin_list.currentItem()
        if not current_item:
            self.output_console.append("Error: No plugin selected")
            return

        plugin_name = current_item.text().split(' ')[0]  # Remove status text

        # Open plugin file in default editor
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "intellicrack", "plugins", "custom_modules")
        plugin_file = os.path.join(plugins_dir, f"{plugin_name}.py")

        if os.path.exists(plugin_file):
            try:
                import platform
                import subprocess

                if platform.system() == "Windows":
                    subprocess.run(['notepad', plugin_file])
                else:
                    subprocess.run(['xdg-open', plugin_file])

                self.log_message(f"Opened plugin '{plugin_name}' for editing")

            except Exception as e:
                self.output_console.append(f"Error opening plugin for editing: {str(e)}")
        else:
            self.output_console.append(f"Plugin file not found: {plugin_file}")

    def populate_network_interfaces(self):
        """Populate network interfaces"""
        self.interface_combo.clear()

        try:
            import psutil

            interfaces = psutil.net_if_addrs()
            for interface_name in interfaces.keys():
                self.interface_combo.addItem(interface_name)

            self.log_message(f"Found {len(interfaces)} network interfaces")

        except Exception as e:
            self.output_console.append(f"Error getting network interfaces: {str(e)}")

    def start_packet_capture(self):
        """Start packet capture"""
        interface = self.interface_combo.currentText()
        filter_text = self.capture_filter_edit.text().strip()

        if not interface:
            self.output_console.append("Error: No interface selected")
            return

        try:
            # Simulate packet capture start
            self.packets_table.setRowCount(0)

            # Add sample packets for demonstration
            sample_packets = [
                ["12:34:56.789", "192.168.1.100", "192.168.1.1", "TCP", "74", "HTTP GET request"],
                ["12:34:56.790", "192.168.1.1", "192.168.1.100", "TCP", "60", "ACK"],
                ["12:34:56.791", "192.168.1.1", "192.168.1.100", "HTTP", "1514", "HTTP Response"],
            ]

            for i, packet in enumerate(sample_packets):
                self.packets_table.insertRow(i)
                for j, data in enumerate(packet):
                    self.packets_table.setItem(i, j, QTableWidgetItem(str(data)))

            self.network_capture_started.emit(interface)
            self.output_console.append(f"Started packet capture on {interface}")
            if filter_text:
                self.output_console.append(f"Using filter: {filter_text}")

            self.log_message(f"Packet capture started on {interface}")

        except Exception as e:
            self.output_console.append(f"Error starting packet capture: {str(e)}")

    def stop_packet_capture(self):
        """Stop packet capture"""
        self.output_console.append("Packet capture stopped")
        self.log_message("Packet capture stopped")

    def save_packet_capture(self):
        """Save packet capture"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Packet Capture",
            "",
            "PCAP Files (*.pcap);;All Files (*)"
        )

        if file_path:
            self.output_console.append(f"Packet capture saved to: {file_path}")
            self.log_message(f"Packet capture saved to: {file_path}")

    def ping_scan(self):
        """Perform ping scan"""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            # Simulate ping scan results
            results = [
                f"Ping scan results for {target}:",
                "Host is up (0.0012s latency)",
                "MAC Address: 00:11:22:33:44:55 (Vendor)",
            ]

            self.tool_output.append("\n".join(results))
            self.log_message(f"Ping scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing ping scan: {str(e)}")

    def port_scan(self):
        """Perform port scan"""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            # Simulate port scan results
            results = [
                f"Port scan results for {target}:",
                "PORT     STATE SERVICE",
                "22/tcp   open  ssh",
                "80/tcp   open  http",
                "443/tcp  open  https",
                "3389/tcp open  ms-wbt-server",
            ]

            self.tool_output.append("\n".join(results))
            self.log_message(f"Port scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing port scan: {str(e)}")

    def service_scan(self):
        """Perform service scan"""
        target = self.scan_target_edit.text().strip()
        if not target:
            self.output_console.append("Error: No target specified")
            return

        try:
            # Simulate service scan results
            results = [
                f"Service scan results for {target}:",
                "PORT     STATE SERVICE    VERSION",
                "22/tcp   open  ssh        OpenSSH 7.4",
                "80/tcp   open  http       Apache httpd 2.4.6",
                "443/tcp  open  ssl/http   Apache httpd 2.4.6",
                "3389/tcp open  ms-wbt-server Microsoft Terminal Services",
            ]

            self.tool_output.append("\n".join(results))
            self.log_message(f"Service scan completed for {target}")

        except Exception as e:
            self.output_console.append(f"Error performing service scan: {str(e)}")

    def log_message(self, message, level="info"):
        """Log message to console or status"""
        if hasattr(self.shared_context, 'log_message'):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")
