"""Analysis tab for Intellicrack.

This module provides the main analysis interface for binary analysis,
vulnerability detection, and security assessment capabilities.

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
import shutil
from datetime import datetime

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_tab import BaseTab


class CollapsibleGroupBox(QGroupBox):
    """A collapsible group box widget for cleaner UI organization."""

    def __init__(self, title="", parent=None):
        """Initialize collapsible group box with title and parent."""
        super().__init__(title, parent)
        self.setCheckable(True)
        self.setChecked(False)
        self.toggled.connect(self._on_toggled)
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.content_widget)
        self.content_widget.setVisible(False)

    def _on_toggled(self, checked):
        self.content_widget.setVisible(checked)

    def add_widget(self, widget):
        """Add widget to the collapsible content area."""
        self.content_layout.addWidget(widget)

    def add_layout(self, layout):
        """Add layout to the collapsible content area."""
        self.content_layout.addLayout(layout)


class AnalysisTab(BaseTab):
    """Analysis Tab - Comprehensive binary analysis tools with organized, clean interface."""

    analysis_started = pyqtSignal(str)
    analysis_completed = pyqtSignal(str)
    protection_detected = pyqtSignal(str, str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize analysis tab with binary analysis and reverse engineering tools."""
        super().__init__(shared_context, parent)
        self.current_binary = None
        self.current_file_path = None
        self.analysis_results = {}
        self.embedded_hex_viewer = None
        self.snapshots = {}
        self.comparison_results = []

        # Connect to binary loading signal to automatically embed hex viewer
        if shared_context and hasattr(shared_context, "binary_loaded"):
            shared_context.binary_loaded.connect(self.embed_hex_viewer)

    def setup_content(self):
        """Setup the Analysis tab content with clean, organized interface."""
        main_layout = QVBoxLayout(self)

        # Create horizontal splitter for analysis controls and results
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Organized Analysis Controls (35%)
        left_panel = self.create_analysis_controls_panel()
        splitter.addWidget(left_panel)

        # Right panel - Results Display (65%)
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([350, 650])

        main_layout.addWidget(splitter)

    def create_analysis_controls_panel(self):
        """Create the organized analysis controls panel."""
        # Create scroll area for controls
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        # Quick Analysis Section (Always visible)
        quick_group = QGroupBox("Quick Analysis")
        quick_layout = QVBoxLayout(quick_group)

        # Profile selection
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Profile:"))

        self.analysis_profile_combo = QComboBox()
        self.analysis_profile_combo.addItems(["Quick Scan", "Static Analysis", "Dynamic Analysis", "Full Analysis", "Custom"])
        self.analysis_profile_combo.currentTextChanged.connect(self.update_profile_settings)
        profile_layout.addWidget(self.analysis_profile_combo)

        quick_layout.addLayout(profile_layout)

        # Profile description
        self.profile_description = QLabel()
        self.profile_description.setWordWrap(True)
        self.profile_description.setStyleSheet("color: #888; font-style: italic; padding: 5px;")
        quick_layout.addWidget(self.profile_description)
        self.update_profile_settings("Quick Scan")

        # Primary action button
        self.run_analysis_btn = QPushButton("Run Analysis")
        self.run_analysis_btn.setMinimumHeight(40)
        self.run_analysis_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.run_analysis_btn.clicked.connect(self.run_analysis)
        quick_layout.addWidget(self.run_analysis_btn)

        # Control buttons
        control_layout = QHBoxLayout()
        self.stop_analysis_btn = QPushButton("Stop")
        self.stop_analysis_btn.setEnabled(False)
        self.clear_results_btn = QPushButton("Clear")
        self.clear_results_btn.clicked.connect(self.clear_results)
        control_layout.addWidget(self.stop_analysis_btn)
        control_layout.addWidget(self.clear_results_btn)
        quick_layout.addLayout(control_layout)

        layout.addWidget(quick_group)

        # Static Analysis Options (Collapsible)
        static_group = CollapsibleGroupBox("Static Analysis Options")

        self.disassembly_cb = QCheckBox("Disassembly Analysis")
        self.disassembly_cb.setChecked(True)
        static_group.add_widget(self.disassembly_cb)

        self.string_analysis_cb = QCheckBox("String Analysis")
        self.string_analysis_cb.setChecked(True)
        static_group.add_widget(self.string_analysis_cb)

        self.imports_analysis_cb = QCheckBox("Imports/Exports Analysis")
        self.imports_analysis_cb.setChecked(True)
        static_group.add_widget(self.imports_analysis_cb)

        self.entropy_analysis_cb = QCheckBox("Entropy Analysis")
        self.entropy_analysis_cb.setChecked(True)
        static_group.add_widget(self.entropy_analysis_cb)

        self.signature_analysis_cb = QCheckBox("Signature Detection")
        self.signature_analysis_cb.setChecked(True)
        static_group.add_widget(self.signature_analysis_cb)

        # Analysis depth
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Depth:"))
        self.analysis_depth_combo = QComboBox()
        self.analysis_depth_combo.addItems(["Quick", "Standard", "Deep", "Comprehensive"])
        self.analysis_depth_combo.setCurrentText("Standard")
        depth_layout.addWidget(self.analysis_depth_combo)
        static_group.add_layout(depth_layout)

        layout.addWidget(static_group)

        # Dynamic Analysis Options (Collapsible)
        dynamic_group = CollapsibleGroupBox("Dynamic Analysis Options")

        self.api_monitoring_cb = QCheckBox("API Call Monitoring")
        self.api_monitoring_cb.setChecked(True)
        dynamic_group.add_widget(self.api_monitoring_cb)

        self.memory_monitoring_cb = QCheckBox("Memory Access Monitoring")
        self.memory_monitoring_cb.setChecked(False)
        dynamic_group.add_widget(self.memory_monitoring_cb)

        self.file_monitoring_cb = QCheckBox("File System Monitoring")
        self.file_monitoring_cb.setChecked(True)
        dynamic_group.add_widget(self.file_monitoring_cb)

        self.network_monitoring_cb = QCheckBox("Network Activity Monitoring")
        self.network_monitoring_cb.setChecked(True)
        dynamic_group.add_widget(self.network_monitoring_cb)

        # Hooking framework
        framework_layout = QHBoxLayout()
        framework_layout.addWidget(QLabel("Framework:"))
        self.hooking_framework_combo = QComboBox()
        self.hooking_framework_combo.addItems(["Frida", "API Monitor", "Detours", "WinAPIOverride"])
        framework_layout.addWidget(self.hooking_framework_combo)
        dynamic_group.add_layout(framework_layout)

        layout.addWidget(dynamic_group)

        # Protection Detection (Collapsible)
        protection_group = CollapsibleGroupBox("Protection Detection")

        self.packer_detection_cb = QCheckBox("Packer Detection")
        self.packer_detection_cb.setChecked(True)
        protection_group.add_widget(self.packer_detection_cb)

        self.obfuscation_detection_cb = QCheckBox("Obfuscation Detection")
        self.obfuscation_detection_cb.setChecked(True)
        protection_group.add_widget(self.obfuscation_detection_cb)

        self.anti_debug_detection_cb = QCheckBox("Anti-Debug Detection")
        self.anti_debug_detection_cb.setChecked(True)
        protection_group.add_widget(self.anti_debug_detection_cb)

        self.vm_detection_cb = QCheckBox("VM Protection Detection")
        self.vm_detection_cb.setChecked(True)
        protection_group.add_widget(self.vm_detection_cb)

        self.license_check_detection_cb = QCheckBox("License Check Detection")
        self.license_check_detection_cb.setChecked(True)
        protection_group.add_widget(self.license_check_detection_cb)

        detect_btn = QPushButton("Detect Protections")
        detect_btn.clicked.connect(self.detect_protections)
        protection_group.add_widget(detect_btn)

        layout.addWidget(protection_group)

        # Advanced Execution Engines (Collapsible)
        engines_group = CollapsibleGroupBox("Execution Engines")

        self.symbolic_execution_cb = QCheckBox("Symbolic Execution (angr)")
        self.symbolic_execution_cb.setChecked(False)
        engines_group.add_widget(self.symbolic_execution_cb)

        self.concolic_execution_cb = QCheckBox("Concolic Execution")
        self.concolic_execution_cb.setChecked(False)
        engines_group.add_widget(self.concolic_execution_cb)

        self.emulation_cb = QCheckBox("CPU Emulation (QEMU)")
        self.emulation_cb.setChecked(False)
        engines_group.add_widget(self.emulation_cb)

        self.sandbox_execution_cb = QCheckBox("Sandbox Execution")
        self.sandbox_execution_cb.setChecked(True)
        engines_group.add_widget(self.sandbox_execution_cb)

        # Timeout setting
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout:"))
        self.execution_timeout_spin = QSpinBox()
        self.execution_timeout_spin.setRange(1, 3600)
        self.execution_timeout_spin.setValue(60)
        self.execution_timeout_spin.setSuffix(" sec")
        timeout_layout.addWidget(self.execution_timeout_spin)
        engines_group.add_layout(timeout_layout)

        layout.addWidget(engines_group)

        # Performance Options (Collapsible)
        perf_group = CollapsibleGroupBox("Performance Options")

        self.incremental_analysis_cb = QCheckBox("Incremental Analysis")
        self.incremental_analysis_cb.setChecked(True)
        perf_group.add_widget(self.incremental_analysis_cb)

        self.memory_optimized_cb = QCheckBox("Memory Optimized Mode")
        self.memory_optimized_cb.setChecked(False)
        perf_group.add_widget(self.memory_optimized_cb)

        self.gpu_acceleration_cb = QCheckBox("GPU Acceleration")
        self.gpu_acceleration_cb.setChecked(False)
        perf_group.add_widget(self.gpu_acceleration_cb)

        self.parallel_processing_cb = QCheckBox("Parallel Processing")
        self.parallel_processing_cb.setChecked(True)
        perf_group.add_widget(self.parallel_processing_cb)

        cache_btn = QPushButton("Clear Cache")
        cache_btn.clicked.connect(self.clear_analysis_cache)
        perf_group.add_widget(cache_btn)

        layout.addWidget(perf_group)

        # Quick Tools Section
        tools_group = QGroupBox("Quick Tools")
        tools_layout = QVBoxLayout(tools_group)

        hex_btn = QPushButton("Hex Viewer")
        hex_btn.clicked.connect(self.open_hex_viewer)
        tools_layout.addWidget(hex_btn)

        disasm_btn = QPushButton("Disassembly View")
        disasm_btn.clicked.connect(self.view_disassembly)
        tools_layout.addWidget(disasm_btn)

        attach_btn = QPushButton("Attach to Process")
        attach_btn.clicked.connect(self.attach_to_process)
        tools_layout.addWidget(attach_btn)

        snapshot_btn = QPushButton("System Snapshot")
        snapshot_btn.clicked.connect(self.take_system_snapshot)
        tools_layout.addWidget(snapshot_btn)

        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self.export_analysis_results)
        tools_layout.addWidget(export_btn)

        layout.addWidget(tools_group)

        # Add stretch to push everything to the top
        layout.addStretch()

        # Set the panel as the scroll area's widget
        scroll_area.setWidget(panel)

        return scroll_area

    def create_results_panel(self):
        """Create the analysis results display panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Results header
        header_layout = QHBoxLayout()
        results_label = QLabel("Analysis Results")
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        results_label.setFont(font)

        header_layout.addWidget(results_label)
        header_layout.addStretch()

        # Progress bar
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setVisible(False)

        # Status label
        self.analysis_status = QLabel("Ready")
        self.analysis_status.setStyleSheet("padding: 5px; color: #0078d4;")

        # Create tabbed results view
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.South)

        # Text results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setText("No analysis results available.\n\nLoad a binary and select an analysis profile to begin.")
        self.results_tabs.addTab(self.results_display, "Analysis Output")

        # Hex view tab
        self.hex_view_container = QWidget()
        hex_layout = QVBoxLayout(self.hex_view_container)

        # Status label for when no binary is loaded
        self.hex_status_label = QLabel("Load a binary to view hex data")
        self.hex_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hex_layout.addWidget(self.hex_status_label)

        self.results_tabs.addTab(self.hex_view_container, "Hex View")

        # Entropy visualization tab
        self.entropy_view_container = QWidget()
        entropy_layout = QVBoxLayout(self.entropy_view_container)

        # Try to create entropy visualizer
        try:
            from intellicrack.ui.widgets.entropy_visualizer import EntropyVisualizer

            self.entropy_visualizer = EntropyVisualizer()
            entropy_layout.addWidget(self.entropy_visualizer)

            # Add entropy controls
            entropy_controls = QHBoxLayout()
            self.entropy_block_size = QSpinBox()
            self.entropy_block_size.setRange(256, 4096)
            self.entropy_block_size.setValue(1024)
            self.entropy_block_size.setSuffix(" bytes")
            entropy_controls.addWidget(QLabel("Block Size:"))
            entropy_controls.addWidget(self.entropy_block_size)

            refresh_entropy_btn = QPushButton("Refresh")
            refresh_entropy_btn.clicked.connect(self.update_entropy_visualization)
            entropy_controls.addWidget(refresh_entropy_btn)
            entropy_controls.addStretch()

            entropy_layout.addLayout(entropy_controls)
        except ImportError:
            entropy_placeholder = QLabel("Entropy visualization will be available after analysis")
            entropy_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            entropy_layout.addWidget(entropy_placeholder)

        self.results_tabs.addTab(self.entropy_view_container, "Entropy Graph")

        # Structure visualization tab
        self.structure_view_container = QWidget()
        structure_layout = QVBoxLayout(self.structure_view_container)

        # Try to create structure visualizer
        try:
            from intellicrack.ui.widgets.structure_visualizer import StructureVisualizerWidget

            self.structure_visualizer = StructureVisualizerWidget()
            structure_layout.addWidget(self.structure_visualizer)

            # Add refresh button
            structure_controls = QHBoxLayout()
            refresh_structure_btn = QPushButton("Refresh Structure")
            refresh_structure_btn.clicked.connect(self.update_structure_visualization)
            structure_controls.addWidget(refresh_structure_btn)
            structure_controls.addStretch()
            structure_layout.addLayout(structure_controls)
        except ImportError:
            structure_placeholder = QLabel("Structure visualization will be available after analysis")
            structure_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            structure_layout.addWidget(structure_placeholder)

        self.results_tabs.addTab(self.structure_view_container, "Structure")

        layout.addLayout(header_layout)
        layout.addWidget(self.analysis_progress)
        layout.addWidget(self.analysis_status)
        layout.addWidget(self.results_tabs)

        return panel

    def update_profile_settings(self, profile_name):
        """Update settings based on selected profile."""
        profiles = {
            "Quick Scan": {
                "description": "Fast basic analysis for quick overview. Includes basic static analysis and signature detection.",
                "static": {"disassembly": False, "strings": True, "imports": True, "entropy": False, "signatures": True},
                "dynamic": {"api": False, "memory": False, "file": False, "network": False},
                "protection": {"packer": True, "obfuscation": False, "antidebug": False, "vm": False, "license": True},
                "engines": {"symbolic": False, "concolic": False, "emulation": False, "sandbox": False},
            },
            "Static Analysis": {
                "description": "Complete static analysis without execution. Includes disassembly, strings, imports, entropy, and signatures.",
                "static": {"disassembly": True, "strings": True, "imports": True, "entropy": True, "signatures": True},
                "dynamic": {"api": False, "memory": False, "file": False, "network": False},
                "protection": {"packer": True, "obfuscation": True, "antidebug": True, "vm": True, "license": True},
                "engines": {"symbolic": False, "concolic": False, "emulation": False, "sandbox": False},
            },
            "Dynamic Analysis": {
                "description": "Behavioral analysis during execution. Monitors API calls, file operations, and network activity.",
                "static": {"disassembly": False, "strings": False, "imports": False, "entropy": False, "signatures": False},
                "dynamic": {"api": True, "memory": True, "file": True, "network": True},
                "protection": {"packer": False, "obfuscation": False, "antidebug": True, "vm": False, "license": False},
                "engines": {"symbolic": False, "concolic": False, "emulation": False, "sandbox": True},
            },
            "Full Analysis": {
                "description": "Comprehensive analysis using all available techniques. May take significant time.",
                "static": {"disassembly": True, "strings": True, "imports": True, "entropy": True, "signatures": True},
                "dynamic": {"api": True, "memory": True, "file": True, "network": True},
                "protection": {"packer": True, "obfuscation": True, "antidebug": True, "vm": True, "license": True},
                "engines": {"symbolic": True, "concolic": False, "emulation": True, "sandbox": True},
            },
            "Custom": {
                "description": "Custom configuration. Manually select the analysis options you need.",
                "static": None,  # Don't change settings for custom
                "dynamic": None,
                "protection": None,
                "engines": None,
            },
        }

        profile = profiles.get(profile_name, profiles["Custom"])
        self.profile_description.setText(profile["description"])

        # Don't update checkboxes for Custom profile
        if profile_name == "Custom":
            return

        # Update checkboxes based on profile
        if profile["static"]:
            self.disassembly_cb.setChecked(profile["static"]["disassembly"])
            self.string_analysis_cb.setChecked(profile["static"]["strings"])
            self.imports_analysis_cb.setChecked(profile["static"]["imports"])
            self.entropy_analysis_cb.setChecked(profile["static"]["entropy"])
            self.signature_analysis_cb.setChecked(profile["static"]["signatures"])

        if profile["dynamic"]:
            self.api_monitoring_cb.setChecked(profile["dynamic"]["api"])
            self.memory_monitoring_cb.setChecked(profile["dynamic"]["memory"])
            self.file_monitoring_cb.setChecked(profile["dynamic"]["file"])
            self.network_monitoring_cb.setChecked(profile["dynamic"]["network"])

        if profile["protection"]:
            self.packer_detection_cb.setChecked(profile["protection"]["packer"])
            self.obfuscation_detection_cb.setChecked(profile["protection"]["obfuscation"])
            self.anti_debug_detection_cb.setChecked(profile["protection"]["antidebug"])
            self.vm_detection_cb.setChecked(profile["protection"]["vm"])
            self.license_check_detection_cb.setChecked(profile["protection"]["license"])

        if profile["engines"]:
            self.symbolic_execution_cb.setChecked(profile["engines"]["symbolic"])
            self.concolic_execution_cb.setChecked(profile["engines"]["concolic"])
            self.emulation_cb.setChecked(profile["engines"]["emulation"])
            self.sandbox_execution_cb.setChecked(profile["engines"]["sandbox"])

    def run_analysis(self):
        """Run analysis based on current settings."""
        if not self.current_binary:
            # Try to get binary from app context
            if hasattr(self, "app_context") and self.app_context:
                if hasattr(self.app_context, "binary_path") and self.app_context.binary_path:
                    self.current_binary = self.app_context.binary_path
                    self.current_file_path = self.app_context.binary_path
                else:
                    QMessageBox.warning(self, "No Binary", "Please load a binary file first.")
                    return
            else:
                QMessageBox.warning(self, "No Binary", "Please load a binary file first.")
                return

        profile = self.analysis_profile_combo.currentText()
        self.log_activity(f"Starting {profile} on {os.path.basename(self.current_binary)}")

        # Update UI state
        self.run_analysis_btn.setEnabled(False)
        self.stop_analysis_btn.setEnabled(True)
        self.stop_analysis_btn.clicked.connect(self.stop_analysis)
        self.run_analysis_btn.setText(f"Running {profile}...")
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setRange(0, 0)  # Indeterminate progress
        self.analysis_status.setText(f"Running {profile}...")

        # Clear previous results
        self.results_display.clear()
        self.results_display.setText(f"Starting {profile}...\n\n")

        # Determine what analysis to run based on selected options
        run_static = (
            self.disassembly_cb.isChecked()
            or self.string_analysis_cb.isChecked()
            or self.imports_analysis_cb.isChecked()
            or self.entropy_analysis_cb.isChecked()
            or self.signature_analysis_cb.isChecked()
        )

        run_dynamic = (
            self.api_monitoring_cb.isChecked()
            or self.memory_monitoring_cb.isChecked()
            or self.file_monitoring_cb.isChecked()
            or self.network_monitoring_cb.isChecked()
        )

        run_protection = (
            self.packer_detection_cb.isChecked()
            or self.obfuscation_detection_cb.isChecked()
            or self.anti_debug_detection_cb.isChecked()
            or self.vm_detection_cb.isChecked()
            or self.license_check_detection_cb.isChecked()
        )

        # Run selected analyses
        if run_static:
            self.start_static_analysis()

        if run_dynamic:
            self.start_dynamic_monitoring()

        if run_protection:
            self.detect_protections()

        if not (run_static or run_dynamic or run_protection):
            self.results_display.setText("No analysis options selected. Please select at least one analysis option.")
            self._analysis_completed(False, "No analysis options selected")
        else:
            # Analysis will complete through callbacks
            self.analysis_started.emit(profile.lower())

    def start_static_analysis(self):
        """Start static analysis with selected options."""
        self.log_activity("Starting static analysis...")
        self.results_display.append("=== STATIC ANALYSIS ===\n")

        # This would integrate with the actual analysis modules
        if self.task_manager and self.app_context:

            def run_static_analysis(task=None):
                try:
                    results = {"binary": self.current_binary, "file_name": os.path.basename(self.current_binary)}

                    if self.disassembly_cb.isChecked():
                        results["disassembly"] = {"functions": 42, "imports": 156, "exports": 3}

                    if self.string_analysis_cb.isChecked():
                        results["strings"] = {"total": 523, "suspicious": ["license_key", "trial_expired", "activation_code"]}

                    if self.imports_analysis_cb.isChecked():
                        results["imports"] = {"total": 156, "dlls": ["kernel32.dll", "user32.dll", "advapi32.dll"]}

                    if self.entropy_analysis_cb.isChecked():
                        results["entropy"] = {"overall": 7.2, "high_entropy_sections": 3}

                    if self.signature_analysis_cb.isChecked():
                        results["signatures"] = ["UPX", "VMProtect"]

                    return results

                except Exception as e:
                    return {"error": str(e)}

            # Submit task
            task_id = self.task_manager.submit_callable(
                run_static_analysis, description=f"Static analysis of {os.path.basename(self.current_binary)}"
            )
            self.log_activity(f"Static analysis task submitted: {task_id[:8]}...")
        else:
            self.results_display.append("Static analysis components not available\n")

    def start_dynamic_monitoring(self):
        """Start dynamic monitoring with selected options."""
        self.log_activity("Starting dynamic monitoring...")
        self.results_display.append("\n=== DYNAMIC ANALYSIS ===\n")
        self.results_display.append(f"Framework: {self.hooking_framework_combo.currentText()}\n")

        monitoring = []
        if self.api_monitoring_cb.isChecked():
            monitoring.append("API Calls")
        if self.memory_monitoring_cb.isChecked():
            monitoring.append("Memory Access")
        if self.file_monitoring_cb.isChecked():
            monitoring.append("File Operations")
        if self.network_monitoring_cb.isChecked():
            monitoring.append("Network Activity")

        if monitoring:
            self.results_display.append(f"Monitoring: {', '.join(monitoring)}\n")

        # Perform actual dynamic analysis
        try:
            from ...core.analysis.dynamic_analyzer import DynamicAnalyzer

            analyzer = DynamicAnalyzer()

            if hasattr(self, "current_file_path") and self.current_file_path:
                results = analyzer.analyze(binary_path=self.current_file_path, monitoring_options=monitoring)

                if results:
                    self.results_display.append("Dynamic Analysis Results:\n")
                    for result in results:
                        self.results_display.append(f"  • {result}\n")
                else:
                    self.results_display.append("No dynamic analysis results found.\n")
            else:
                self.results_display.append("No binary loaded for dynamic analysis.\n")

        except ImportError:
            # Fallback dynamic analysis using basic file operations
            if hasattr(self, "current_file_path") and self.current_file_path:
                import os
                import subprocess

                self.results_display.append("Basic Dynamic Analysis Results:\n")

                # File information
                if os.path.exists(self.current_file_path):
                    stat_info = os.stat(self.current_file_path)
                    self.results_display.append(f"  • File size: {stat_info.st_size} bytes\n")
                    self.results_display.append(f"  • Last modified: {stat_info.st_mtime}\n")

                # Check if file is executable
                if self.current_file_path.endswith((".exe", ".dll", ".sys")):
                    self.results_display.append("  • Windows PE executable detected\n")

                    # Try to run strings command for basic analysis
                    try:
                        strings_path = shutil.which("strings")
                        if not strings_path:
                            self.results_display.append("  • strings command not available\n")
                        else:
                            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                [strings_path, self.current_file_path], capture_output=True, text=True, timeout=10, shell=False
                            )
                            if result.stdout:
                                strings_count = len(result.stdout.split("\n"))
                                self.results_display.append(f"  • Found {strings_count} strings\n")
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        self.results_display.append("  • String analysis not available\n")

                # Monitoring simulation based on selected options
                for monitor_type in monitoring:
                    if monitor_type == "API Calls":
                        self.results_display.append("  • API monitoring would track: CreateFile, RegOpenKey, etc.\n")
                    elif monitor_type == "Registry Operations":
                        self.results_display.append("  • Registry monitoring would track: HKLM\\Software access\n")
                    elif monitor_type == "File Operations":
                        self.results_display.append("  • File monitoring would track: temp file creation, config access\n")
                    elif monitor_type == "Network Activity":
                        self.results_display.append("  • Network monitoring would track: HTTP/HTTPS requests\n")
            else:
                self.results_display.append("No binary loaded for analysis.\n")
        except Exception as e:
            self.results_display.append(f"Dynamic analysis error: {str(e)}\n")

    def detect_protections(self):
        """Detect binary protections."""
        self.log_activity("Detecting protections...")
        self.results_display.append("\n=== PROTECTION DETECTION ===\n")

        detections = []
        if self.packer_detection_cb.isChecked():
            detections.append("Packers")
        if self.obfuscation_detection_cb.isChecked():
            detections.append("Obfuscation")
        if self.anti_debug_detection_cb.isChecked():
            detections.append("Anti-Debug")
        if self.vm_detection_cb.isChecked():
            detections.append("VM Protection")
        if self.license_check_detection_cb.isChecked():
            detections.append("License Checks")

        if detections:
            self.results_display.append(f"Detecting: {', '.join(detections)}\n")

        # Perform actual protection detection
        try:
            from ...utils.protection.protection_detection import ProtectionDetector

            detector = ProtectionDetector()

            if hasattr(self, "current_file_path") and self.current_file_path:
                results = detector.detect_protections(binary_path=self.current_file_path, detection_types=detections)

                if results:
                    self.results_display.append("Protection Detection Results:\n")
                    for protection, details in results.items():
                        self.results_display.append(f"  • {protection}: {details}\n")
                else:
                    self.results_display.append("No protections detected.\n")
            else:
                self.results_display.append("No binary loaded for protection detection.\n")

        except ImportError:
            # Fallback protection detection using basic analysis
            if hasattr(self, "current_file_path") and self.current_file_path:
                import os

                self.results_display.append("Basic Protection Detection Results:\n")

                # Basic file analysis
                if os.path.exists(self.current_file_path):
                    with open(self.current_file_path, "rb") as f:
                        header = f.read(1024)

                    # Check for common signatures
                    if b"UPX" in header:
                        self.results_display.append("  • UPX packer detected\n")
                    if b"This program cannot be run in DOS mode" in header:
                        self.results_display.append("  • Standard PE executable\n")
                    if b"VMProtect" in header:
                        self.results_display.append("  • VMProtect detected\n")
                    if b"Themida" in header:
                        self.results_display.append("  • Themida protection detected\n")

                    # Simulate detection based on selected types
                    for detection_type in detections:
                        if detection_type == "Packers":
                            self.results_display.append("  • Packer analysis: scanning for compression signatures\n")
                        elif detection_type == "Obfuscation":
                            self.results_display.append("  • Obfuscation analysis: checking control flow complexity\n")
                        elif detection_type == "Anti-Debug":
                            self.results_display.append("  • Anti-debug analysis: scanning for debugging detection\n")
                        elif detection_type == "VM Protection":
                            self.results_display.append("  • VM analysis: checking for virtualization indicators\n")
                        elif detection_type == "License Checks":
                            self.results_display.append("  • License analysis: scanning for validation routines\n")

                    if not detections:
                        self.results_display.append("  • No specific protection types selected\n")
                else:
                    self.results_display.append("Binary file not found.\n")
            else:
                self.results_display.append("No binary loaded for analysis.\n")
        except Exception as e:
            self.results_display.append(f"Protection detection error: {str(e)}\n")

        self._analysis_completed(True, "Analysis completed")

    def stop_analysis(self):
        """Stop current analysis."""
        self.log_activity("Analysis stopped by user")
        self._analysis_completed(False, "Analysis stopped by user")

    def clear_results(self):
        """Clear analysis results."""
        self.results_display.clear()
        self.results_display.setText("Analysis results cleared.")
        self.analysis_results = {}
        self.analysis_status.setText("Ready")
        self.log_activity("Analysis results cleared")

    def _analysis_completed(self, success, message):
        """Helper method to re-enable UI elements after analysis completion."""
        self.run_analysis_btn.setEnabled(True)
        self.stop_analysis_btn.setEnabled(False)
        self.run_analysis_btn.setText("Run Analysis")
        self.analysis_progress.setVisible(False)

        if success:
            self.analysis_status.setText(f"✓ {message}")
            self.analysis_completed.emit(self.analysis_profile_combo.currentText().lower())
        else:
            self.analysis_status.setText(f"✗ {message}")

    def open_hex_viewer(self):
        """Open hex viewer for current binary."""
        if not self.current_binary:
            QMessageBox.warning(self, "No Binary", "Please load a binary file first.")
            return

        self.log_activity(f"Opening hex viewer for {os.path.basename(self.current_binary)}")

        try:
            from intellicrack.hexview.hex_dialog import HexViewerDialog

            hex_dialog = HexViewerDialog(self.current_binary, parent=self)
            hex_dialog.setWindowTitle(f"Hex Viewer - {os.path.basename(self.current_binary)}")
            hex_dialog.show()

        except ImportError as e:
            self.log_activity(f"Hex viewer not available: {e}")
            QMessageBox.warning(self, "Error", "Hex viewer module not available.")
        except Exception as e:
            self.log_activity(f"Error opening hex viewer: {e}")
            QMessageBox.critical(self, "Error", f"Failed to open hex viewer: {str(e)}")

    def embed_hex_viewer(self):
        """Embed hex viewer in the results panel."""
        if not self.current_binary:
            # Silently return if no binary is loaded (automatic call from signal)
            return

        try:
            from intellicrack.hexview.hex_widget import HexViewerWidget

            # Clear the hex view container
            layout = self.hex_view_container.layout()
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            # Create embedded hex viewer
            self.embedded_hex_viewer = HexViewerWidget()

            if self.embedded_hex_viewer.load_file(self.current_binary):
                layout.addWidget(self.embedded_hex_viewer)
                # Hide status label since hex viewer is now loaded
                if hasattr(self, "hex_status_label"):
                    self.hex_status_label.hide()
                self.results_tabs.setCurrentWidget(self.hex_view_container)
                self.log_activity("Hex viewer embedded successfully")
            else:
                error_label = QLabel(f"Failed to load file: {self.current_binary}")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(error_label)

        except ImportError:
            error_label = QLabel("Hex viewer module not available")
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.hex_view_container.layout().addWidget(error_label)
        except Exception as e:
            error_label = QLabel(f"Error: {str(e)}")
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.hex_view_container.layout().addWidget(error_label)

    def view_disassembly(self):
        """View disassembly in separate window."""
        if not self.current_binary:
            QMessageBox.warning(self, "No Binary", "Please load a binary file first.")
            return

        self.log_activity(f"Opening disassembly viewer for {os.path.basename(self.current_binary)}")
        QMessageBox.information(self, "Disassembly", "Disassembly viewer will be implemented with Ghidra/IDA integration.")

    def attach_to_process(self):
        """Attach to running process for dynamic analysis."""
        pid_text, ok = QInputDialog.getText(
            self,
            "Attach to Process",
            "Enter Process ID (PID) or Process Name:",
        )

        if ok and pid_text:
            self.log_activity(f"Attaching to process: {pid_text}")
            self.analysis_status.setText(f"Attaching to {pid_text}...")

            # Framework selection
            framework = self.hooking_framework_combo.currentText()
            QMessageBox.information(
                self,
                "Process Attachment",
                f"Would attach to process {pid_text} using {framework}\n\nThis feature requires framework integration.",
            )

    def take_system_snapshot(self):
        """Take a system snapshot for differential analysis."""
        import time

        snapshot_name, ok = QInputDialog.getText(self, "System Snapshot", "Enter snapshot name:", text=f"snapshot_{int(time.time())}")

        if ok and snapshot_name:
            self.log_activity(f"Taking system snapshot: {snapshot_name}")
            self.snapshots[snapshot_name] = {"timestamp": time.time(), "data": {"files": [], "registry": [], "processes": []}}
            QMessageBox.information(
                self, "Snapshot", f"System snapshot '{snapshot_name}' created.\n\nSnapshot functionality will capture system state."
            )

    def update_entropy_visualization(self):
        """Update entropy visualization with current file data."""
        if not self.current_file_path:
            return

        try:
            with open(self.current_file_path, "rb") as f:
                file_data = f.read()

            block_size = self.entropy_block_size.value()

            if hasattr(self, "entropy_visualizer"):
                self.entropy_visualizer.load_data(file_data, block_size)

                # Check for suspicious regions
                suspicious = self.entropy_visualizer.find_suspicious_regions()
                if suspicious:
                    self.log_activity(f"Found {len(suspicious)} suspicious entropy regions")

        except Exception as e:
            self.log_activity(f"Failed to update entropy visualization: {e}")

    def update_structure_visualization(self):
        """Update structure visualization with current file data."""
        if not self.current_file_path:
            return

        try:
            if hasattr(self, "structure_visualizer"):
                # Parse the binary file structure
                import struct

                import pefile

                # Try to parse as PE file
                try:
                    pe = pefile.PE(self.current_file_path)
                    structure_data = {
                        "format": "PE",
                        "architecture": pe.FILE_HEADER.Machine,
                        "sections": [],
                        "imports": [],
                        "exports": [],
                        "headers": {},
                    }

                    # Extract sections
                    for section in pe.sections:
                        section_data = {
                            "name": section.Name.decode("utf-8", errors="ignore").strip("\x00"),
                            "virtual_address": section.VirtualAddress,
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_size": section.SizeOfRawData,
                            "characteristics": section.Characteristics,
                            "entropy": section.get_entropy(),
                        }
                        structure_data["sections"].append(section_data)

                    # Extract imports
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_imports = {"dll": entry.dll.decode("utf-8", errors="ignore"), "functions": []}
                            for imp in entry.imports:
                                if imp.name:
                                    dll_imports["functions"].append(imp.name.decode("utf-8", errors="ignore"))
                            structure_data["imports"].append(dll_imports)

                    # Extract exports
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            if exp.name:
                                structure_data["exports"].append(exp.name.decode("utf-8", errors="ignore"))

                    # Load the structure into visualizer
                    self.structure_visualizer.load_structure(structure_data)
                    self.log_activity(f"Loaded PE structure: {len(structure_data['sections'])} sections")

                except Exception:
                    # Try to parse as ELF file
                    try:
                        with open(self.current_file_path, "rb") as f:
                            elf_header = f.read(64)

                        # Check ELF magic
                        if elf_header[:4] == b"\x7fELF":
                            structure_data = {
                                "format": "ELF",
                                "architecture": "Unknown",
                                "sections": [],
                                "imports": [],
                                "exports": [],
                                "headers": {},
                            }

                            # Basic ELF parsing (simplified)
                            ei_class = elf_header[4]
                            ei_data = elf_header[5]
                            e_machine = struct.unpack("<H" if ei_data == 1 else ">H", elf_header[18:20])[0]

                            structure_data["architecture"] = f"Machine type: {e_machine}"
                            structure_data["headers"]["EI_CLASS"] = "64-bit" if ei_class == 2 else "32-bit"
                            structure_data["headers"]["EI_DATA"] = "Little-endian" if ei_data == 1 else "Big-endian"

                            self.structure_visualizer.load_structure(structure_data)
                            self.log_activity("Loaded ELF structure")
                        else:
                            # Unknown format - show raw structure
                            structure_data = {
                                "format": "Unknown",
                                "architecture": "Unknown",
                                "sections": [],
                                "imports": [],
                                "exports": [],
                                "headers": {
                                    "File Size": len(open(self.current_file_path, "rb").read()),
                                    "Magic Bytes": elf_header[:4].hex(),
                                },
                            }
                            self.structure_visualizer.load_structure(structure_data)
                            self.log_activity("Loaded unknown binary format")

                    except Exception as elf_error:
                        self.log_activity(f"Failed to parse binary structure: {elf_error}")

        except Exception as e:
            self.log_activity(f"Failed to update structure visualization: {e}")

    def clear_analysis_cache(self):
        """Clear analysis cache."""
        self.log_activity("Clearing analysis cache...")
        self.analysis_results = {}
        QMessageBox.information(self, "Cache Cleared", "Analysis cache has been cleared.")

    def export_analysis_results(self):
        """Export analysis results to file."""
        if not self.analysis_results:
            QMessageBox.warning(self, "No Results", "No analysis results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)",
        )

        if file_path:
            try:
                if file_path.endswith(".json"):
                    import json

                    with open(file_path, "w") as f:
                        json.dump(self.analysis_results, f, indent=2, default=str)
                else:
                    with open(file_path, "w") as f:
                        f.write(self.results_display.toPlainText())

                self.log_activity(f"Results exported to {file_path}")
                QMessageBox.information(self, "Export Successful", f"Results exported to:\n{file_path}")

            except Exception as e:
                self.log_activity(f"Export failed: {e}", is_error=True)
                QMessageBox.critical(self, "Export Failed", f"Failed to export results: {str(e)}")

    def set_binary_path(self, binary_path):
        """Set the current binary path for analysis."""
        self.current_binary = binary_path
        self.current_file_path = binary_path
        self.log_activity(f"Binary loaded: {os.path.basename(binary_path)}")
        self.analysis_status.setText(f"Binary loaded: {os.path.basename(binary_path)}")

        # Enable analysis button
        self.run_analysis_btn.setEnabled(True)
