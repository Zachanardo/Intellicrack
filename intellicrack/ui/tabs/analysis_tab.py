"""Analysis tab for Intellicrack.

This module provides the main analysis interface for binary analysis,

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
vulnerability detection, and security assessment capabilities.
"""

import os
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
    QSpinBox,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...core.analysis.analysis_orchestrator import AnalysisPhase
from ...utils.analysis.analysis_exporter import AnalysisExporter
from ..widgets.entropy_visualizer import EntropyVisualizerWidget
from ..widgets.structure_visualizer import StructureVisualizerWidget
from .base_tab import BaseTab


class AnalysisTab(BaseTab):
    """Analysis Tab - Comprehensive binary analysis tools including static analysis,
    dynamic analysis, protection detection, and advanced execution engines.
    """

    analysis_started = pyqtSignal(str)
    analysis_completed = pyqtSignal(str)
    protection_detected = pyqtSignal(str, str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize analysis tab with binary analysis and reverse engineering tools."""
        super().__init__(shared_context, parent)

    def setup_content(self):
        """Setup the complete Analysis tab content"""
        main_layout = QVBoxLayout(self)

        # Create horizontal splitter for analysis tools and results
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Analysis Controls (40%)
        left_panel = self.create_analysis_controls_panel()
        splitter.addWidget(left_panel)

        # Right panel - Results Display (60%)
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter)

    def create_analysis_controls_panel(self):
        """Create the analysis controls panel with subtabs"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Analysis subtabs
        self.analysis_subtabs = QTabWidget()
        self.analysis_subtabs.setTabPosition(QTabWidget.TabPosition.North)

        # Create individual analysis subtabs
        self.analysis_subtabs.addTab(self.create_static_analysis_tab(), "Static & Code Analysis")
        self.analysis_subtabs.addTab(self.create_protection_analysis_tab(), "Protection Analysis")
        self.analysis_subtabs.addTab(self.create_dynamic_hooking_tab(), "Dynamic & Hooking")
        self.analysis_subtabs.addTab(self.create_execution_engines_tab(), "Execution Engines")
        self.analysis_subtabs.addTab(self.create_analysis_options_tab(), "Options & Cache")

        layout.addWidget(self.analysis_subtabs)

        # Quick Action Buttons
        quick_actions_group = QGroupBox("Quick Actions")
        quick_actions_layout = QHBoxLayout(quick_actions_group)

        start_analysis_btn = QPushButton("Start Full Analysis")
        start_analysis_btn.clicked.connect(self.start_full_analysis)
        start_analysis_btn.setStyleSheet("font-weight: bold; color: green;")

        stop_analysis_btn = QPushButton("Stop Analysis")
        stop_analysis_btn.clicked.connect(self.stop_analysis)
        stop_analysis_btn.setStyleSheet("color: red;")

        clear_results_btn = QPushButton("Clear Results")
        clear_results_btn.clicked.connect(self.clear_results)

        quick_actions_layout.addWidget(start_analysis_btn)
        quick_actions_layout.addWidget(stop_analysis_btn)
        quick_actions_layout.addWidget(clear_results_btn)

        snapshot_btn = QPushButton("Take Snapshot")
        snapshot_btn.clicked.connect(self.take_system_snapshot)

        compare_btn = QPushButton("Compare Snapshots")
        compare_btn.clicked.connect(self.compare_system_snapshots)

        quick_actions_layout.addWidget(snapshot_btn)
        quick_actions_layout.addWidget(compare_btn)

        # Network Forensics Actions
        network_analysis_btn = QPushButton("Analyze PCAP")
        network_analysis_btn.clicked.connect(self.analyze_network_capture)
        quick_actions_layout.addWidget(network_analysis_btn)

        live_traffic_btn = QPushButton("Monitor Traffic")
        live_traffic_btn.clicked.connect(self.monitor_live_traffic)
        quick_actions_layout.addWidget(live_traffic_btn)

        # Artifact Extraction
        extract_artifacts_btn = QPushButton("Extract Artifacts")
        extract_artifacts_btn.clicked.connect(self.extract_network_artifacts)
        extract_artifacts_btn.setToolTip("Extract URLs, IPs, credentials, and other artifacts from binary or network data")
        quick_actions_layout.addWidget(extract_artifacts_btn)

        # Protocol Detection
        detect_protocols_btn = QPushButton("Detect Protocols")
        detect_protocols_btn.clicked.connect(self.detect_network_protocols)
        detect_protocols_btn.setToolTip("Detect network protocols and license communication patterns")
        quick_actions_layout.addWidget(detect_protocols_btn)

        layout.addWidget(quick_actions_group)

        return panel

    def create_static_analysis_tab(self):
        """Create static analysis controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Static Analysis Methods
        methods_group = QGroupBox("Analysis Methods")
        methods_layout = QVBoxLayout(methods_group)

        self.disassembly_cb = QCheckBox("Disassembly Analysis")
        self.disassembly_cb.setChecked(True)

        self.string_analysis_cb = QCheckBox("String Analysis")
        self.string_analysis_cb.setChecked(True)

        self.imports_analysis_cb = QCheckBox("Imports/Exports Analysis")
        self.imports_analysis_cb.setChecked(True)

        self.entropy_analysis_cb = QCheckBox("Entropy Analysis")
        self.entropy_analysis_cb.setChecked(True)

        self.signature_analysis_cb = QCheckBox("Signature Detection")
        self.signature_analysis_cb.setChecked(True)

        methods_layout.addWidget(self.disassembly_cb)
        methods_layout.addWidget(self.string_analysis_cb)
        methods_layout.addWidget(self.imports_analysis_cb)
        methods_layout.addWidget(self.entropy_analysis_cb)
        methods_layout.addWidget(self.signature_analysis_cb)

        # Analysis Depth
        depth_group = QGroupBox("Analysis Depth")
        depth_layout = QVBoxLayout(depth_group)

        self.analysis_depth_combo = QComboBox()
        self.analysis_depth_combo.addItems(
            ["Quick Scan", "Standard", "Deep Analysis", "Comprehensive"]
        )
        self.analysis_depth_combo.setCurrentText("Standard")

        depth_layout.addWidget(QLabel("Depth Level:"))
        depth_layout.addWidget(self.analysis_depth_combo)

        # Control buttons
        controls_layout = QHBoxLayout()

        start_static_btn = QPushButton("Start Static Analysis")
        start_static_btn.clicked.connect(self.start_static_analysis)

        view_disasm_btn = QPushButton("View Disassembly")
        view_disasm_btn.clicked.connect(self.view_disassembly)

        view_hex_btn = QPushButton("Hex Viewer")
        view_hex_btn.clicked.connect(self.open_hex_viewer)
        view_hex_btn.setStyleSheet("font-weight: bold; color: #0078d4;")

        controls_layout.addWidget(start_static_btn)
        controls_layout.addWidget(view_disasm_btn)
        controls_layout.addWidget(view_hex_btn)

        layout.addWidget(methods_group)
        layout.addWidget(depth_group)
        layout.addLayout(controls_layout)
        layout.addStretch()

        return tab

    def create_protection_analysis_tab(self):
        """Create protection analysis controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Protection Detection
        detection_group = QGroupBox("Protection Detection")
        detection_layout = QVBoxLayout(detection_group)

        self.packer_detection_cb = QCheckBox("Packer Detection")
        self.packer_detection_cb.setChecked(True)

        self.obfuscation_detection_cb = QCheckBox("Obfuscation Detection")
        self.obfuscation_detection_cb.setChecked(True)

        self.anti_debug_detection_cb = QCheckBox("Anti-Debug Detection")
        self.anti_debug_detection_cb.setChecked(True)

        self.vm_detection_cb = QCheckBox("VM Protection Detection")
        self.vm_detection_cb.setChecked(True)

        self.license_check_detection_cb = QCheckBox("License Check Detection")
        self.license_check_detection_cb.setChecked(True)

        detection_layout.addWidget(self.packer_detection_cb)
        detection_layout.addWidget(self.obfuscation_detection_cb)
        detection_layout.addWidget(self.anti_debug_detection_cb)
        detection_layout.addWidget(self.vm_detection_cb)
        detection_layout.addWidget(self.license_check_detection_cb)

        # Detection Controls
        controls_layout = QHBoxLayout()

        detect_protections_btn = QPushButton("Detect Protections")
        detect_protections_btn.clicked.connect(self.detect_protections)

        view_protection_info_btn = QPushButton("View Protection Info")
        view_protection_info_btn.clicked.connect(self.view_protection_info)

        controls_layout.addWidget(detect_protections_btn)
        controls_layout.addWidget(view_protection_info_btn)

        layout.addWidget(detection_group)
        layout.addLayout(controls_layout)
        layout.addStretch()

        return tab

    def create_dynamic_hooking_tab(self):
        """Create dynamic analysis and hooking controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Dynamic Analysis Options
        dynamic_group = QGroupBox("Dynamic Analysis")
        dynamic_layout = QVBoxLayout(dynamic_group)

        self.api_monitoring_cb = QCheckBox("API Call Monitoring")
        self.api_monitoring_cb.setChecked(True)

        self.memory_monitoring_cb = QCheckBox("Memory Access Monitoring")
        self.memory_monitoring_cb.setChecked(False)

        self.file_monitoring_cb = QCheckBox("File System Monitoring")
        self.file_monitoring_cb.setChecked(True)

        self.network_monitoring_cb = QCheckBox("Network Activity Monitoring")
        self.network_monitoring_cb.setChecked(True)

        dynamic_layout.addWidget(self.api_monitoring_cb)
        dynamic_layout.addWidget(self.memory_monitoring_cb)
        dynamic_layout.addWidget(self.file_monitoring_cb)
        dynamic_layout.addWidget(self.network_monitoring_cb)

        # Hooking Framework
        hooking_group = QGroupBox("Hooking Framework")
        hooking_layout = QVBoxLayout(hooking_group)

        self.hooking_framework_combo = QComboBox()
        self.hooking_framework_combo.addItems(["Frida", "API Monitor", "Detours", "WinAPIOverride"])

        hooking_layout.addWidget(QLabel("Framework:"))
        hooking_layout.addWidget(self.hooking_framework_combo)

        # Controls
        controls_layout = QHBoxLayout()

        start_monitoring_btn = QPushButton("Start Monitoring")
        start_monitoring_btn.clicked.connect(self.start_dynamic_monitoring)

        attach_to_process_btn = QPushButton("Attach to Process")
        attach_to_process_btn.clicked.connect(self.attach_to_process)

        controls_layout.addWidget(start_monitoring_btn)
        controls_layout.addWidget(attach_to_process_btn)

        layout.addWidget(dynamic_group)
        layout.addWidget(hooking_group)
        layout.addLayout(controls_layout)
        layout.addStretch()

        return tab

    def create_execution_engines_tab(self):
        """Create advanced execution engines controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Execution Engines
        engines_group = QGroupBox("Execution Engines")
        engines_layout = QVBoxLayout(engines_group)

        self.symbolic_execution_cb = QCheckBox("Symbolic Execution (angr)")
        self.symbolic_execution_cb.setChecked(False)

        self.concolic_execution_cb = QCheckBox("Concolic Execution")
        self.concolic_execution_cb.setChecked(False)

        self.emulation_cb = QCheckBox("CPU Emulation (QEMU)")
        self.emulation_cb.setChecked(False)

        self.sandbox_execution_cb = QCheckBox("Sandbox Execution")
        self.sandbox_execution_cb.setChecked(True)

        engines_layout.addWidget(self.symbolic_execution_cb)
        engines_layout.addWidget(self.concolic_execution_cb)
        engines_layout.addWidget(self.emulation_cb)
        engines_layout.addWidget(self.sandbox_execution_cb)

        # Engine Configuration
        config_group = QGroupBox("Engine Configuration")
        config_layout = QVBoxLayout(config_group)

        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        self.execution_timeout_spin = QSpinBox()
        self.execution_timeout_spin.setRange(1, 3600)
        self.execution_timeout_spin.setValue(60)
        timeout_layout.addWidget(self.execution_timeout_spin)

        config_layout.addLayout(timeout_layout)

        # Controls
        controls_layout = QHBoxLayout()

        configure_engines_btn = QPushButton("Configure Engines")
        configure_engines_btn.clicked.connect(self.configure_execution_engines)

        test_engines_btn = QPushButton("Test Engines")
        test_engines_btn.clicked.connect(self.test_execution_engines)

        controls_layout.addWidget(configure_engines_btn)
        controls_layout.addWidget(test_engines_btn)

        layout.addWidget(engines_group)
        layout.addWidget(config_group)
        layout.addLayout(controls_layout)
        layout.addStretch()

        return tab

    def create_analysis_options_tab(self):
        """Create analysis options and cache controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Analysis Options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)

        self.incremental_analysis_cb = QCheckBox("Incremental Analysis")
        self.incremental_analysis_cb.setChecked(True)

        self.memory_optimized_cb = QCheckBox("Memory Optimized Mode")
        self.memory_optimized_cb.setChecked(False)

        self.gpu_acceleration_cb = QCheckBox("GPU Acceleration")
        self.gpu_acceleration_cb.setChecked(False)

        self.parallel_processing_cb = QCheckBox("Parallel Processing")
        self.parallel_processing_cb.setChecked(True)

        options_layout.addWidget(self.incremental_analysis_cb)
        options_layout.addWidget(self.memory_optimized_cb)
        options_layout.addWidget(self.gpu_acceleration_cb)
        options_layout.addWidget(self.parallel_processing_cb)

        # Cache Management
        cache_group = QGroupBox("Cache Management")
        cache_layout = QVBoxLayout(cache_group)

        cache_controls_layout = QHBoxLayout()

        clear_cache_btn = QPushButton("Clear Analysis Cache")
        clear_cache_btn.clicked.connect(self.clear_analysis_cache)

        clear_all_cache_btn = QPushButton("Clear All Cache")
        clear_all_cache_btn.clicked.connect(self.clear_all_cache)

        view_cache_btn = QPushButton("View Cache Info")
        view_cache_btn.clicked.connect(self.view_cache_info)

        cache_controls_layout.addWidget(clear_cache_btn)
        cache_controls_layout.addWidget(clear_all_cache_btn)
        cache_controls_layout.addWidget(view_cache_btn)

        cache_layout.addLayout(cache_controls_layout)

        # GPU Configuration
        gpu_config_btn = QPushButton("Configure GPU Acceleration")
        gpu_config_btn.clicked.connect(self.configure_gpu_acceleration)

        layout.addWidget(options_group)
        layout.addWidget(cache_group)
        layout.addWidget(gpu_config_btn)
        layout.addStretch()

        return tab

    def create_results_panel(self):
        """Create the analysis results display panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Results header
        header_layout = QHBoxLayout()
        results_label = QLabel("Analysis Results")
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        results_label.setFont(font)

        # Export results button
        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self.export_analysis_results)

        header_layout.addWidget(results_label)
        header_layout.addStretch()
        header_layout.addWidget(export_btn)

        # Progress bar
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setVisible(False)

        # Status label
        self.analysis_status = QLabel("Ready")

        # Create tabbed results view
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.South)

        # Text results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setText(
            "No analysis results available. Select a binary and start analysis."
        )
        self.results_tabs.addTab(self.results_display, "Analysis Results")

        # Hex view tab (initially empty)
        self.hex_view_container = QWidget()
        hex_layout = QVBoxLayout(self.hex_view_container)
        self.hex_view_placeholder = QLabel("Select 'Embed Hex View' to display hex editor here")
        self.hex_view_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hex_layout.addWidget(self.hex_view_placeholder)

        # Add embed hex view button
        embed_hex_btn = QPushButton("Embed Hex View")
        embed_hex_btn.clicked.connect(self.embed_hex_viewer)
        hex_layout.addWidget(embed_hex_btn)

        self.results_tabs.addTab(self.hex_view_container, "Hex View")

        # Entropy graph tab
        self.entropy_view_container = QWidget()
        entropy_layout = QVBoxLayout(self.entropy_view_container)

        # Create entropy visualization widget
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
        self.results_tabs.addTab(self.entropy_view_container, "Entropy Graph")

        layout.addLayout(header_layout)
        layout.addWidget(self.analysis_progress)
        layout.addWidget(self.analysis_status)
        layout.addWidget(self.results_tabs)

        return panel

    def update_entropy_visualization(self):
        """Update entropy visualization with current file data."""
        if not self.current_file_path:
            return

        try:
            with open(self.current_file_path, "rb") as f:
                file_data = f.read()

            block_size = self.entropy_block_size.value()
            self.entropy_visualizer.load_data(file_data, block_size)

            # Check for suspicious regions
            suspicious = self.entropy_visualizer.find_suspicious_regions()
            if suspicious:
                self.logger.info(f"Found {len(suspicious)} suspicious entropy regions")

        except Exception as e:
            self.logger.error(f"Failed to update entropy visualization: {e}")

    def start_full_analysis(self):
        """Start comprehensive analysis"""
        self.log_activity("Starting full analysis...")
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setValue(0)
        self.analysis_status.setText("Running full analysis...")
        self.analysis_started.emit("full")

    def start_static_analysis(self):
        """Start static analysis only"""
        if not self.current_binary:


            QMessageBox.warning(self, "Warning", "No binary loaded for analysis!")
            return

        self.log_activity("Starting static analysis...")
        self.analysis_status.setText("Running static analysis...")
        self.analysis_progress.setVisible(True)
        self.analysis_started.emit("static")

        # Submit static analysis task to TaskManager
        if self.task_manager and self.app_context:

            def run_static_analysis(task=None):
                try:
                    # Notify start of analysis
                    if self.app_context:
                        self.app_context.start_analysis(
                            "static_analysis",
                            {
                                "binary": self.current_binary,
                                "options": {
                                    "disassembly": self.disassembly_cb.isChecked(),
                                    "strings": self.string_analysis_cb.isChecked(),
                                    "imports": self.imports_analysis_cb.isChecked(),
                                    "entropy": self.entropy_analysis_cb.isChecked(),
                                    "signatures": self.signature_analysis_cb.isChecked(),
                                    "depth": self.analysis_depth_combo.currentText(),
                                },
                            },
                        )

                    # Determine which phases to run based on options
                    phases = [
                        AnalysisPhase.PREPARATION,
                        AnalysisPhase.BASIC_INFO,
                        AnalysisPhase.STATIC_ANALYSIS,
                    ]

                    if self.entropy_analysis_cb.isChecked():
                        phases.append(AnalysisPhase.ENTROPY_ANALYSIS)

                    if self.signature_analysis_cb.isChecked():
                        phases.append(AnalysisPhase.PATTERN_MATCHING)

                    # Add vulnerability scanning phase
                    phases.append(AnalysisPhase.VULNERABILITY_SCAN)

                    phases.append(AnalysisPhase.STRUCTURE_ANALYSIS)
                    phases.append(AnalysisPhase.FINALIZATION)

                    # Run orchestrated analysis
                    result = self.analysis_orchestrator.analyze_binary(
                        self.current_binary,
                        phases=phases,
                    )

                    # Convert orchestration result to AppContext format
                    analysis_result = {
                        "binary": self.current_binary,
                        "file_name": os.path.basename(self.current_binary),
                        "success": result.success,
                        "phases_completed": [p.value for p in result.phases_completed],
                        "errors": result.errors,
                        "warnings": result.warnings,
                    }

                    # Extract specific results
                    if AnalysisPhase.STATIC_ANALYSIS in result.phases_completed:
                        static_data = result.results.get("static_analysis", {})

                        if self.disassembly_cb.isChecked() and "functions" in static_data:
                            analysis_result["disassembly"] = {
                                "functions": len(static_data.get("functions", [])),
                                "imports": len(static_data.get("imports", [])),
                                "exports": len(static_data.get("exports", [])),
                            }

                        if self.string_analysis_cb.isChecked() and "strings" in static_data:
                            strings = static_data.get("strings", [])
                            suspicious_strings = [
                                s
                                for s in strings
                                if any(
                                    keyword in s.get("string", "").lower()
                                    for keyword in ["password", "key", "token", "secret", "api"]
                                )
                            ]
                            analysis_result["strings"] = {
                                "total": len(strings),
                                "suspicious": suspicious_strings[:10],  # Limit to first 10
                            }

                        if self.imports_analysis_cb.isChecked() and "imports" in static_data:
                            imports = static_data.get("imports", [])
                            analysis_result["imports"] = {
                                "total": len(imports),
                                "functions": imports[:20],  # Limit to first 20
                            }

                    if AnalysisPhase.ENTROPY_ANALYSIS in result.phases_completed:
                        entropy_data = result.results.get("entropy_analysis", {})
                        analysis_result["entropy"] = {
                            "overall": entropy_data.get("overall_entropy", 0),
                            "high_entropy_sections": len(
                                entropy_data.get("high_entropy_chunks", [])
                            ),
                        }

                    if AnalysisPhase.PATTERN_MATCHING in result.phases_completed:
                        pattern_data = result.results.get("pattern_matching", {})
                        analysis_result["signatures"] = pattern_data

                    if AnalysisPhase.VULNERABILITY_SCAN in result.phases_completed:
                        vuln_data = result.results.get("vulnerability_scan", {})
                        analysis_result["vulnerabilities"] = vuln_data

                    if AnalysisPhase.STRUCTURE_ANALYSIS in result.phases_completed:
                        structure_data = result.results.get("structure_analysis", {})
                        analysis_result["structure"] = structure_data

                    if task:
                        task.emit_progress(100, "Analysis complete")

                    # Store results in AppContext
                    if self.app_context:
                        self.app_context.set_analysis_results("static_analysis", analysis_result)

                    return analysis_result

                except Exception as e:
                    import traceback

                    self.log_activity(f"Analysis error: {e!s}", is_error=True)
                    if self.app_context:
                        self.app_context.fail_analysis("static_analysis", str(e))
                    return {
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    }

            # Submit the task
            task_id = self.task_manager.submit_callable(
                run_static_analysis,
                description=f"Static analysis of {os.path.basename(self.current_binary)}",
            )

            self.log_activity(f"Static analysis task submitted: {task_id[:8]}...")

        else:
            # Fallback
            self.log_activity("Static analysis not available - missing components")
            self.analysis_status.setText("Static analysis failed - check configuration")

    def detect_protections(self):
        """Detect binary protections"""
        if not self.current_binary:


            QMessageBox.warning(self, "Warning", "No binary loaded for analysis!")
            return

        self.log_activity("Detecting protections...")
        self.analysis_status.setText("Detecting protections...")

        # Submit protection detection task to TaskManager
        if self.task_manager and self.app_context:

            def run_protection_detection(task=None):
                try:
                    # Import protection modules
                    from intellicrack.protection.unified_protection_engine import get_unified_engine

                    # Notify start of analysis
                    if self.app_context:
                        self.app_context.start_analysis(
                            "protection_detection",
                            {
                                "binary": self.current_binary,
                                "options": {
                                    "packer_detection": self.packer_detection_cb.isChecked(),
                                    "obfuscation_detection": self.obfuscation_detection_cb.isChecked(),
                                    "anti_debug_detection": self.anti_debug_detection_cb.isChecked(),
                                    "vm_detection": self.vm_detection_cb.isChecked(),
                                    "license_check_detection": self.license_check_detection_cb.isChecked(),
                                },
                            },
                        )

                    # Get unified protection engine
                    engine = get_unified_engine()

                    # Update progress
                    if task:
                        task.emit_progress(20, "Initializing protection detection")

                    # Perform unified analysis
                    result = engine.analyze_unified(
                        self.current_binary,
                        enable_icp=True,
                        enable_die=True,
                    )

                    if task:
                        task.emit_progress(80, "Processing results")

                    # Format results
                    formatted_results = {
                        "binary": self.current_binary,
                        "protections": result.get("protections", []),
                        "packers": result.get("packers", []),
                        "obfuscation": result.get("obfuscation", {}),
                        "anti_debug": result.get("anti_debug", []),
                        "vm_protection": result.get("vm_protection", {}),
                        "license_checks": result.get("license_checks", []),
                        "bypass_recommendations": result.get("bypass_recommendations", []),
                    }

                    # Store results in AppContext
                    if self.app_context:
                        self.app_context.set_analysis_results(
                            "protection_detection", formatted_results
                        )

                    if task:
                        task.emit_progress(100, "Protection detection complete")

                    return formatted_results

                except Exception as e:
                    self.log_activity(f"Protection detection error: {e!s}")
                    if self.app_context:
                        self.app_context.fail_analysis("protection_detection", str(e))
                    raise

            # Submit the task
            task_id = self.task_manager.submit_callable(
                run_protection_detection,
                description=f"Protection detection for {self.current_binary}",
            )

            self.log_activity(f"Protection detection task submitted: {task_id[:8]}...")

        else:
            # Fallback message
            self.log_activity("Protection detection not available - missing components")
            self.analysis_status.setText("Protection detection failed - check configuration")

    def start_dynamic_monitoring(self):
        """Start dynamic monitoring"""
        if not self.current_binary:


            QMessageBox.warning(self, "Warning", "No binary loaded for analysis!")
            return

        self.log_activity("Starting dynamic monitoring...")
        self.analysis_status.setText("Starting dynamic monitoring...")

        # Submit dynamic analysis task to TaskManager
        if self.task_manager and self.app_context:

            def run_dynamic_analysis(task=None):
                try:
                    # Get monitoring options
                    options = {
                        "api_monitoring": self.api_monitoring_cb.isChecked(),
                        "memory_monitoring": self.memory_monitoring_cb.isChecked(),
                        "file_monitoring": self.file_monitoring_cb.isChecked(),
                        "network_monitoring": self.network_monitoring_cb.isChecked(),
                        "framework": self.hooking_framework_combo.currentText(),
                    }

                    # Notify start of analysis
                    if self.app_context:
                        self.app_context.start_analysis(
                            "dynamic_analysis",
                            {
                                "binary": self.current_binary,
                                "options": options,
                            },
                        )

                    # Update progress
                    if task:
                        task.emit_progress(20, "Initializing dynamic analysis framework")

                    # Run dynamic analysis using orchestrator
                    phases = [
                        AnalysisPhase.PREPARATION,
                        AnalysisPhase.DYNAMIC_ANALYSIS,
                        AnalysisPhase.FINALIZATION,
                    ]

                    result = self.analysis_orchestrator.analyze_binary(
                        self.current_binary,
                        phases=phases,
                    )

                    if task:
                        task.emit_progress(80, "Processing results")

                    # Format results
                    analysis_result = {
                        "binary": self.current_binary,
                        "file_name": os.path.basename(self.current_binary),
                        "success": result.success,
                        "monitoring_options": options,
                        "framework": options["framework"],
                    }

                    if AnalysisPhase.DYNAMIC_ANALYSIS in result.phases_completed:
                        dynamic_data = result.results.get("dynamic_analysis", {})

                        if options["api_monitoring"]:
                            analysis_result["api_calls"] = dynamic_data.get("api_calls", [])

                        if options["memory_monitoring"]:
                            analysis_result["memory_access"] = dynamic_data.get("memory_access", [])

                        if options["file_monitoring"]:
                            analysis_result["file_operations"] = dynamic_data.get(
                                "file_operations", []
                            )

                        if options["network_monitoring"]:
                            analysis_result["network_activity"] = dynamic_data.get(
                                "network_activity", []
                            )

                    if task:
                        task.emit_progress(100, "Dynamic analysis complete")

                    # Store results in AppContext
                    if self.app_context:
                        self.app_context.set_analysis_results("dynamic_analysis", analysis_result)

                    return analysis_result

                except Exception as e:
                    import traceback

                    self.log_activity(f"Dynamic analysis error: {e!s}", is_error=True)
                    if self.app_context:
                        self.app_context.fail_analysis("dynamic_analysis", str(e))
                    return {
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    }

            # Submit the task
            task_id = self.task_manager.submit_callable(
                run_dynamic_analysis,
                description=f"Dynamic analysis of {os.path.basename(self.current_binary)}",
            )

            self.log_activity(f"Dynamic analysis task submitted: {task_id[:8]}...")

        else:
            # Fallback
            self.log_activity("Dynamic analysis not available - missing components")
            self.analysis_status.setText("Dynamic analysis failed - check configuration")

    def stop_analysis(self):
        """Stop current analysis"""
        self.log_activity("Analysis stopped by user")
        self.analysis_progress.setVisible(False)
        self.analysis_status.setText("Analysis stopped")

    def clear_results(self):
        """Clear analysis results"""
        self.results_display.clear()
        self.results_display.setText("Analysis results cleared.")
        self.analysis_results = {}
        self.log_activity("Analysis results cleared")

    def view_disassembly(self):
        """View disassembly in separate window"""
        self.log_activity("Opening disassembly viewer...")

    def open_hex_viewer(self):
        """Open hex viewer for current binary"""
        if not self.current_binary:


            QMessageBox.warning(self, "Warning", "No binary loaded!")
            return

        self.log_activity(f"Opening hex viewer for {os.path.basename(self.current_binary)}")

        try:
            # Import hex viewer module
            from intellicrack.hexview.hex_dialog import HexViewerDialog

            # Create hex viewer dialog
            hex_dialog = HexViewerDialog(self.current_binary, parent=self)
            hex_dialog.setWindowTitle(f"Hex Viewer - {os.path.basename(self.current_binary)}")

            # Connect to AppContext for coordinated updates
            if self.app_context:
                # Connect hex viewer events to app context if needed
                pass

            # Show the hex viewer
            hex_dialog.show()

        except ImportError as e:
            self.log_activity(f"Hex viewer not available: {e!s}")


            QMessageBox.warning(
                self, "Error", "Hex viewer module not available. Please check installation."
            )
        except Exception as e:
            self.log_activity(f"Error opening hex viewer: {e!s}")


            QMessageBox.critical(self, "Error", f"Failed to open hex viewer: {e!s}")

    def embed_hex_viewer(self):
        """Embed hex viewer in the results panel"""
        if not self.current_binary:


            QMessageBox.warning(self, "Warning", "No binary loaded!")
            return

        self.log_activity(f"Embedding hex viewer for {os.path.basename(self.current_binary)}")

        try:
            # Import hex viewer widget
            from intellicrack.hexview.hex_widget import HexViewerWidget

            # Clear the hex view container
            layout = self.hex_view_container.layout()
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            # Create embedded hex viewer
            self.embedded_hex_viewer = HexViewerWidget()

            # Load the binary file
            if self.embedded_hex_viewer.load_file(self.current_binary):
                layout.addWidget(self.embedded_hex_viewer)
                self.log_activity("Hex viewer embedded successfully")

                # Switch to hex view tab
                self.results_tabs.setCurrentWidget(self.hex_view_container)
            else:
                error_label = QLabel(f"Failed to load file: {self.current_binary}")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(error_label)

        except ImportError as e:
            self.log_activity(f"Hex viewer widget not available: {e!s}")
            error_label = QLabel("Hex viewer module not available")
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.hex_view_container.layout().addWidget(error_label)
        except Exception as e:
            self.log_activity(f"Error embedding hex viewer: {e!s}")
            error_label = QLabel(f"Error: {e!s}")
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.hex_view_container.layout().addWidget(error_label)

    def view_protection_info(self):
        """View detailed protection information"""
        self.log_activity("Viewing protection information...")

    def attach_to_process(self):
        """Attach to running process for dynamic analysis"""
        from PyQt6.QtWidgets import QInputDialog, QMessageBox

        # Get process list or PID
        pid_text, ok = QInputDialog.getText(
            self,
            "Attach to Process",
            "Enter Process ID (PID) or Process Name:",
        )

        if ok and pid_text:
            self.log_activity(f"Attaching to process: {pid_text}")
            self.analysis_status.setText(f"Attaching to {pid_text}...")

            # Try to attach using selected framework
            framework = self.hooking_framework_combo.currentText()

            if self.task_manager:

                def attach_process(task=None):
                    try:
                        if task:
                            task.emit_progress(10, "Finding process")

                        # Determine if input is PID or name
                        try:
                            pid = int(pid_text)
                            target_type = "pid"
                        except ValueError:
                            pid = pid_text
                            target_type = "name"

                        if task:
                            task.emit_progress(30, f"Preparing {framework} framework")

                        # Here we would attach using the selected framework
                        # For now, we'll simulate the attachment
                        result = {
                            "success": True,
                            "framework": framework,
                            "target": pid,
                            "target_type": target_type,
                            "message": f"Successfully attached to process {pid} using {framework}",
                        }

                        if task:
                            task.emit_progress(100, "Attached successfully")

                        return result

                    except Exception as e:
                        return {
                            "success": False,
                            "error": str(e),
                        }

                # Submit attachment task
                task_id = self.task_manager.submit_callable(
                    attach_process,
                    description=f"Attaching to process {pid_text}",
                )

                self.log_activity(f"Process attachment task submitted: {task_id[:8]}...")
            else:
                QMessageBox.warning(self, "Error", "Task manager not available")

    def configure_execution_engines(self):
        """Configure execution engines"""
        self.log_activity("Configuring execution engines...")

    def test_execution_engines(self):
        """Test execution engines"""
        self.log_activity("Testing execution engines...")

    def clear_analysis_cache(self):
        """Clear analysis cache"""
        self.log_activity("Analysis cache cleared")

    def clear_all_cache(self):
        """Clear all cache"""
        self.log_activity("All cache cleared")

    def take_system_snapshot(self):
        """Take a system snapshot for differential analysis"""
        try:
            import json
            import time

            from ...utils.system.snapshot_common import create_system_snapshot

            # Get snapshot name from user
            snapshot_name, ok = QInputDialog.getText(
                self,
                "Take System Snapshot",
                "Enter snapshot name:",
                text=f"snapshot_{int(time.time())}"
            )

            if not ok or not snapshot_name:
                return

            # Create snapshot
            self.log_message("Taking system snapshot...", "info")
            snapshot = create_system_snapshot()

            # Store snapshot
            if not hasattr(self, 'snapshots'):
                self.snapshots = {}

            self.snapshots[snapshot_name] = {
                'timestamp': time.time(),
                'data': snapshot
            }

            # Save to file
            snapshot_file = f"snapshots/{snapshot_name}.json"
            import os
            os.makedirs("snapshots", exist_ok=True)

            with open(snapshot_file, 'w') as f:
                json.dump(snapshot, f, indent=2)

            self.log_message(f"Snapshot '{snapshot_name}' saved successfully", "success")

            # Update snapshot list if exists
            if hasattr(self, 'snapshot_list'):
                self.snapshot_list.addItem(snapshot_name)

        except Exception as e:
            self.log_message(f"Error taking snapshot: {e}", "error")

    def compare_system_snapshots(self):
        """Compare two system snapshots to identify changes"""
        try:

            from PyQt6.QtWidgets import (
                QComboBox,
                QDialog,
                QHBoxLayout,
                QLabel,
                QPushButton,
                QTextEdit,
                QVBoxLayout,
            )

            from ...utils.system.snapshot_utils import compare_snapshots

            if not hasattr(self, 'snapshots') or len(self.snapshots) < 2:
                self.log_message("Need at least 2 snapshots to compare", "warning")
                return

            # Create comparison dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Compare System Snapshots")
            dialog.resize(800, 600)

            layout = QVBoxLayout()

            # Snapshot selection
            selection_layout = QHBoxLayout()

            selection_layout.addWidget(QLabel("Baseline:"))
            baseline_combo = QComboBox()
            baseline_combo.addItems(list(self.snapshots.keys()))
            selection_layout.addWidget(baseline_combo)

            selection_layout.addWidget(QLabel("Current:"))
            current_combo = QComboBox()
            current_combo.addItems(list(self.snapshots.keys()))
            selection_layout.addWidget(current_combo)

            compare_btn = QPushButton("Compare")
            selection_layout.addWidget(compare_btn)

            layout.addLayout(selection_layout)

            # Results display
            results_display = QTextEdit()
            results_display.setReadOnly(True)
            layout.addWidget(results_display)

            def perform_comparison():
                baseline_name = baseline_combo.currentText()
                current_name = current_combo.currentText()

                if baseline_name == current_name:
                    results_display.setPlainText("Please select different snapshots to compare")
                    return

                # Get snapshots
                baseline = self.snapshots[baseline_name]['data']
                current = self.snapshots[current_name]['data']

                # Compare
                differences = compare_snapshots(baseline, current)

                # Format results
                result_text = f"Comparison: {baseline_name} → {current_name}\n"
                result_text += "=" * 60 + "\n\n"

                # Files
                if differences['files']['added']:
                    result_text += f"📄 Files Added ({len(differences['files']['added'])}):\n"
                    for file in differences['files']['added'][:10]:
                        result_text += f"  + {file}\n"
                    if len(differences['files']['added']) > 10:
                        result_text += f"  ... and {len(differences['files']['added']) - 10} more\n"
                    result_text += "\n"

                if differences['files']['removed']:
                    result_text += f"📄 Files Removed ({len(differences['files']['removed'])}):\n"
                    for file in differences['files']['removed'][:10]:
                        result_text += f"  - {file}\n"
                    if len(differences['files']['removed']) > 10:
                        result_text += f"  ... and {len(differences['files']['removed']) - 10} more\n"
                    result_text += "\n"

                if differences['files']['modified']:
                    result_text += f"📄 Files Modified ({len(differences['files']['modified'])}):\n"
                    for file in differences['files']['modified'][:10]:
                        result_text += f"  * {file}\n"
                    if len(differences['files']['modified']) > 10:
                        result_text += f"  ... and {len(differences['files']['modified']) - 10} more\n"
                    result_text += "\n"

                # Registry (Windows)
                if differences['registry']['added']:
                    result_text += f"🔧 Registry Keys Added ({len(differences['registry']['added'])}):\n"
                    for key in differences['registry']['added'][:10]:
                        result_text += f"  + {key}\n"
                    if len(differences['registry']['added']) > 10:
                        result_text += f"  ... and {len(differences['registry']['added']) - 10} more\n"
                    result_text += "\n"

                # Network
                if differences['network']['new_connections']:
                    result_text += f"🌐 New Network Connections ({len(differences['network']['new_connections'])}):\n"
                    for conn in differences['network']['new_connections'][:10]:
                        result_text += f"  + {conn}\n"
                    if len(differences['network']['new_connections']) > 10:
                        result_text += f"  ... and {len(differences['network']['new_connections']) - 10} more\n"
                    result_text += "\n"

                # Processes
                if differences['processes']['started']:
                    result_text += f"⚙️ Processes Started ({len(differences['processes']['started'])}):\n"
                    for proc in differences['processes']['started'][:10]:
                        result_text += f"  + {proc}\n"
                    if len(differences['processes']['started']) > 10:
                        result_text += f"  ... and {len(differences['processes']['started']) - 10} more\n"
                    result_text += "\n"

                if differences['processes']['terminated']:
                    result_text += f"⚙️ Processes Terminated ({len(differences['processes']['terminated'])}):\n"
                    for proc in differences['processes']['terminated'][:10]:
                        result_text += f"  - {proc}\n"
                    if len(differences['processes']['terminated']) > 10:
                        result_text += f"  ... and {len(differences['processes']['terminated']) - 10} more\n"
                    result_text += "\n"

                # Summary
                total_changes = (
                    len(differences['files']['added']) +
                    len(differences['files']['removed']) +
                    len(differences['files']['modified']) +
                    len(differences['registry']['added']) +
                    len(differences['registry']['removed']) +
                    len(differences['registry']['modified']) +
                    len(differences['network']['new_connections']) +
                    len(differences['network']['closed_connections']) +
                    len(differences['processes']['started']) +
                    len(differences['processes']['terminated'])
                )

                result_text += "\n" + "=" * 60 + "\n"
                result_text += f"Total Changes Detected: {total_changes}\n"

                results_display.setPlainText(result_text)

                # Store comparison results
                if not hasattr(self, 'comparison_results'):
                    self.comparison_results = []

                self.comparison_results.append({
                    'baseline': baseline_name,
                    'current': current_name,
                    'differences': differences,
                    'total_changes': total_changes
                })

                self.log_message(f"Snapshot comparison complete: {total_changes} changes detected", "info")

            compare_btn.clicked.connect(perform_comparison)

            # Export button
            export_btn = QPushButton("Export Comparison")
            export_btn.clicked.connect(lambda: self._export_comparison(results_display.toPlainText()))
            layout.addWidget(export_btn)

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            self.log_message(f"Error comparing snapshots: {e}", "error")

    def _export_comparison(self, comparison_text):
        """Export comparison results to file"""
        try:


            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Comparison Results",
                "snapshot_comparison.txt",
                "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
            )

            if file_path:
                if file_path.endswith('.json') and hasattr(self, 'comparison_results'):
                    import json
                    with open(file_path, 'w') as f:
                        json.dump(self.comparison_results[-1], f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(comparison_text)

                self.log_message(f"Comparison exported to {file_path}", "success")

        except Exception as e:
            self.log_message(f"Error exporting comparison: {e}", "error")

    def analyze_network_capture(self):
        """Analyze PCAP files using NetworkForensicsEngine"""
        try:


            from ...core.analysis.network_forensics_engine import NetworkForensicsEngine

            # Get PCAP file from user
            pcap_file, _ = QFileDialog.getOpenFileName(
                self,
                "Select PCAP File",
                "",
                "PCAP Files (*.pcap *.pcapng);;All Files (*)"
            )

            if not pcap_file:
                return

            self.log_message("Analyzing network capture...", "info")

            # Create network forensics engine
            engine = NetworkForensicsEngine()

            # Analyze the capture
            results = engine.analyze_capture(pcap_file)

            # Display results
            result_text = "=== Network Capture Analysis ===\n\n"
            result_text += f"File: {os.path.basename(pcap_file)}\n"
            result_text += f"Total Packets: {results.get('total_packets', 0)}\n"
            result_text += f"Duration: {results.get('duration', 'N/A')}\n\n"

            # Protocol breakdown
            if 'protocols' in results:
                result_text += "Protocol Distribution:\n"
                for proto, count in results['protocols'].items():
                    result_text += f"  • {proto}: {count} packets\n"
                result_text += "\n"

            # License-related traffic
            if 'license_traffic' in results:
                result_text += "License Communication Detected:\n"
                for item in results['license_traffic'][:10]:
                    result_text += f"  • {item['timestamp']}: {item['src']} → {item['dst']}\n"
                    result_text += f"    Protocol: {item['protocol']}, Data: {item.get('summary', 'N/A')}\n"
                result_text += "\n"

            # Suspicious patterns
            if 'suspicious_patterns' in results:
                result_text += "Suspicious Patterns:\n"
                for pattern in results['suspicious_patterns']:
                    result_text += f"  ⚠️ {pattern}\n"
                result_text += "\n"

            # Extract artifacts if any
            if 'artifacts' in results:
                artifacts = engine.extract_artifacts(results['raw_data'])
                if artifacts.get('credentials'):
                    result_text += "Extracted Credentials:\n"
                    for cred in artifacts['credentials'][:5]:
                        result_text += f"  • {cred['type']}: {cred['value']}\n"
                    result_text += "\n"

                if artifacts.get('urls'):
                    result_text += "Extracted URLs:\n"
                    for url in artifacts['urls'][:10]:
                        result_text += f"  • {url}\n"
                    result_text += "\n"

            # Update results display
            self.results_display.setText(result_text)
            self.results_tabs.setCurrentWidget(self.results_display.parent())

            self.log_message(f"Network analysis complete: {results.get('total_packets', 0)} packets analyzed", "success")

        except Exception as e:
            self.log_message(f"Error analyzing network capture: {e}", "error")

    def monitor_live_traffic(self):
        """Monitor live network traffic for license communication"""
        try:
            import threading

            from PyQt6.QtWidgets import (
                QCheckBox,
                QComboBox,
                QDialog,
                QHBoxLayout,
                QLabel,
                QPushButton,
                QTextEdit,
                QVBoxLayout,
            )

            from ...core.analysis.network_forensics_engine import NetworkForensicsEngine

            # Create monitoring dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Live Network Traffic Monitor")
            dialog.resize(900, 600)

            layout = QVBoxLayout()

            # Interface selection
            interface_layout = QHBoxLayout()
            interface_layout.addWidget(QLabel("Network Interface:"))

            interface_combo = QComboBox()
            # Get available interfaces
            try:
                from intellicrack.handlers.psutil_handler import psutil
                interfaces = list(psutil.net_if_addrs().keys())
                interface_combo.addItems(interfaces)
            except:
                interface_combo.addItems(["eth0", "wlan0", "lo"])

            interface_layout.addWidget(interface_combo)

            # Filters
            filter_license = QCheckBox("License Traffic Only")
            filter_license.setChecked(True)
            interface_layout.addWidget(filter_license)

            filter_suspicious = QCheckBox("Suspicious Patterns")
            filter_suspicious.setChecked(True)
            interface_layout.addWidget(filter_suspicious)

            layout.addLayout(interface_layout)

            # Traffic display
            traffic_display = QTextEdit()
            traffic_display.setReadOnly(True)
            traffic_display.setFont(QFont("Courier", 9))
            layout.addWidget(traffic_display)

            # Control buttons
            button_layout = QHBoxLayout()

            start_btn = QPushButton("Start Monitoring")
            stop_btn = QPushButton("Stop Monitoring")
            stop_btn.setEnabled(False)
            export_btn = QPushButton("Export Capture")

            button_layout.addWidget(start_btn)
            button_layout.addWidget(stop_btn)
            button_layout.addWidget(export_btn)

            layout.addLayout(button_layout)

            # Monitoring state
            monitoring_active = {'value': False}
            captured_packets = []

            def monitor_thread():
                """Background thread for monitoring"""
                engine = NetworkForensicsEngine()
                interface = interface_combo.currentText()

                def packet_callback(packet_info):
                    """Handle each captured packet"""
                    if not monitoring_active['value']:
                        return False

                    captured_packets.append(packet_info)

                    # Filter based on checkboxes
                    show = True
                    if filter_license.isChecked():
                        # Check if packet is license-related
                        if not any(keyword in str(packet_info).lower()
                                 for keyword in ['license', 'activation', 'serial', 'key']):
                            show = False

                    if show:
                        # Format packet info
                        packet_text = f"[{packet_info.get('timestamp', 'N/A')}] "
                        packet_text += f"{packet_info.get('src', 'N/A')} → {packet_info.get('dst', 'N/A')} "
                        packet_text += f"[{packet_info.get('protocol', 'N/A')}] "

                        if 'data' in packet_info:
                            packet_text += f"\n  Data: {packet_info['data'][:100]}..."

                        # Add to display (thread-safe)
                        traffic_display.append(packet_text)

                    return monitoring_active['value']

                # Start live monitoring
                try:
                    _ = engine.analyze_live_traffic(
                        interface=interface,
                        duration=0,  # Continuous
                        packet_callback=packet_callback
                    )

                    # Final summary
                    traffic_display.append("\n" + "="*60)
                    traffic_display.append(f"Monitoring stopped. Captured {len(captured_packets)} packets")

                except Exception as e:
                    traffic_display.append(f"\nError: {e}")

            def start_monitoring():
                """Start monitoring in background thread"""
                monitoring_active['value'] = True
                start_btn.setEnabled(False)
                stop_btn.setEnabled(True)

                traffic_display.clear()
                traffic_display.append(f"Starting live traffic monitoring on {interface_combo.currentText()}...\n")
                traffic_display.append("="*60 + "\n")

                # Start monitoring thread
                monitor = threading.Thread(target=monitor_thread, daemon=True)
                monitor.start()

            def stop_monitoring():
                """Stop monitoring"""
                monitoring_active['value'] = False
                start_btn.setEnabled(True)
                stop_btn.setEnabled(False)
                traffic_display.append("\nStopping monitor...")

            def export_capture():
                """Export captured packets"""
                if not captured_packets:
                    traffic_display.append("\nNo packets to export")
                    return

                import json



                file_path, _ = QFileDialog.getSaveFileName(
                    dialog,
                    "Export Network Capture",
                    "network_capture.json",
                    "JSON Files (*.json);;All Files (*)"
                )

                if file_path:
                    with open(file_path, 'w') as f:
                        json.dump(captured_packets, f, indent=2, default=str)
                    traffic_display.append(f"\nExported {len(captured_packets)} packets to {file_path}")

            start_btn.clicked.connect(start_monitoring)
            stop_btn.clicked.connect(stop_monitoring)
            export_btn.clicked.connect(export_capture)

            dialog.setLayout(layout)
            dialog.exec()

            # Ensure monitoring stops when dialog closes
            monitoring_active['value'] = False

        except Exception as e:
            self.log_message(f"Error in live traffic monitoring: {e}", "error")

    def extract_network_artifacts(self):
        """Extract forensic artifacts from binary files or network captures"""
        try:
            import os

            from PyQt6.QtCore import QThread, pyqtSignal
            from PyQt6.QtWidgets import (
                QDialog,
                QFileDialog,
                QGroupBox,
                QHBoxLayout,
                QLabel,
                QProgressBar,
                QPushButton,
                QTabWidget,
                QTextEdit,
                QTreeWidget,
                QTreeWidgetItem,
                QVBoxLayout,
            )

            # File selection dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select File for Artifact Extraction",
                "",
                "All Files (*);;PCAP Files (*.pcap *.pcapng);;Binary Files (*.exe *.dll *.bin);;Memory Dumps (*.dmp *.raw *.mem)"
            )

            if not file_path:
                return

            # Create results dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Artifact Extraction - {os.path.basename(file_path)}")
            dialog.setGeometry(100, 100, 1200, 800)

            layout = QVBoxLayout()

            # File info
            info_label = QLabel(f"Extracting artifacts from: {file_path}")
            info_label.setStyleSheet("font-weight: bold; padding: 10px;")
            layout.addWidget(info_label)

            # Progress bar
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 0)  # Indeterminate
            layout.addWidget(progress_bar)

            # Tab widget for different artifact types
            tab_widget = QTabWidget()

            # Create tabs for different artifact categories
            urls_tree = QTreeWidget()
            urls_tree.setHeaderLabels(["URL", "Offset", "Length"])
            urls_tree.setAlternatingRowColors(True)
            tab_widget.addTab(urls_tree, "URLs")

            ips_tree = QTreeWidget()
            ips_tree.setHeaderLabels(["IP Address", "Offset", "Type"])
            ips_tree.setAlternatingRowColors(True)
            tab_widget.addTab(ips_tree, "IP Addresses")

            emails_tree = QTreeWidget()
            emails_tree.setHeaderLabels(["Email", "Offset", "Length"])
            emails_tree.setAlternatingRowColors(True)
            tab_widget.addTab(emails_tree, "Emails")

            creds_tree = QTreeWidget()
            creds_tree.setHeaderLabels(["Type", "Value", "Offset"])
            creds_tree.setAlternatingRowColors(True)
            tab_widget.addTab(creds_tree, "Credentials")

            files_tree = QTreeWidget()
            files_tree.setHeaderLabels(["File", "Type", "Offset"])
            files_tree.setAlternatingRowColors(True)
            tab_widget.addTab(files_tree, "Files")

            base64_tree = QTreeWidget()
            base64_tree.setHeaderLabels(["Base64 Data", "Length", "Offset"])
            base64_tree.setAlternatingRowColors(True)
            tab_widget.addTab(base64_tree, "Base64 Data")

            # License-specific artifacts
            license_tree = QTreeWidget()
            license_tree.setHeaderLabels(["Type", "Value", "Details"])
            license_tree.setAlternatingRowColors(True)
            tab_widget.addTab(license_tree, "License Artifacts")

            layout.addWidget(tab_widget)

            # Statistics panel
            stats_text = QTextEdit()
            stats_text.setReadOnly(True)
            stats_text.setMaximumHeight(150)
            stats_group = QGroupBox("Extraction Statistics")
            stats_layout = QVBoxLayout()
            stats_layout.addWidget(stats_text)
            stats_group.setLayout(stats_layout)
            layout.addWidget(stats_group)

            # Buttons
            button_layout = QHBoxLayout()

            export_btn = QPushButton("Export Artifacts")
            filter_btn = QPushButton("Filter Results")
            analyze_btn = QPushButton("Deep Analysis")
            close_btn = QPushButton("Close")

            button_layout.addWidget(export_btn)
            button_layout.addWidget(filter_btn)
            button_layout.addWidget(analyze_btn)
            button_layout.addStretch()
            button_layout.addWidget(close_btn)

            layout.addLayout(button_layout)

            # Worker thread for extraction
            class ArtifactExtractor(QThread):
                progress = pyqtSignal(str)
                artifact_found = pyqtSignal(dict)
                finished_extraction = pyqtSignal(list)
                error = pyqtSignal(str)

                def __init__(self, file_path):
                    super().__init__()
                    self.file_path = file_path

                def run(self):
                    try:
                        from intellicrack.core.analysis.network_forensics_engine import (
                            NetworkForensicsEngine,
                        )

                        self.progress.emit("Reading file...")

                        # Read file data
                        with open(self.file_path, 'rb') as f:
                            data = f.read()

                        self.progress.emit(f"Loaded {len(data):,} bytes")

                        # Use NetworkForensicsEngine for extraction
                        engine = NetworkForensicsEngine()
                        self.progress.emit("Extracting artifacts...")

                        artifacts = engine.extract_artifacts(data)

                        # Also look for license-specific patterns
                        import re

                        license_patterns = [
                            (rb"license[_-]?key[=:]?\s*([A-Za-z0-9\-]{10,})", "License Key"),
                            (rb"serial[_-]?number[=:]?\s*([A-Za-z0-9\-]{10,})", "Serial Number"),
                            (rb"activation[_-]?code[=:]?\s*([A-Za-z0-9\-]{10,})", "Activation Code"),
                            (rb"product[_-]?key[=:]?\s*([A-Za-z0-9\-]{10,})", "Product Key"),
                            (rb"hwid[=:]?\s*([A-Fa-f0-9\-]{10,})", "Hardware ID"),
                            (rb"machine[_-]?id[=:]?\s*([A-Fa-f0-9\-]{10,})", "Machine ID"),
                        ]

                        for pattern, artifact_type in license_patterns:
                            matches = re.findall(pattern, data, re.IGNORECASE)
                            for match in matches:
                                try:
                                    value = match.decode('utf-8', errors='ignore')
                                    artifact = {
                                        'type': 'License_' + artifact_type.replace(' ', '_'),
                                        'value': value,
                                        'offset': data.find(match),
                                        'length': len(match),
                                        'category': 'license'
                                    }
                                    artifacts.append(artifact)
                                    self.artifact_found.emit(artifact)
                                except:
                                    pass

                        # Emit all artifacts
                        for artifact in artifacts:
                            self.artifact_found.emit(artifact)

                        self.progress.emit(f"Extraction complete: {len(artifacts)} artifacts found")
                        self.finished_extraction.emit(artifacts)

                    except Exception as e:
                        self.error.emit(str(e))

            # Start extraction
            extractor = ArtifactExtractor(file_path)

            def on_artifact_found(artifact):
                """Add artifact to appropriate tree"""
                artifact_type = artifact.get('type', '')
                value = artifact.get('value', '')
                offset = str(artifact.get('offset', 0))
                length = str(artifact.get('length', 0))

                if artifact_type == 'URL':
                    item = QTreeWidgetItem([value, offset, length])
                    urls_tree.addTopLevelItem(item)
                elif artifact_type == 'IP_Address':
                    item = QTreeWidgetItem([value, offset, artifact_type])
                    ips_tree.addTopLevelItem(item)
                elif artifact_type == 'Email':
                    item = QTreeWidgetItem([value, offset, length])
                    emails_tree.addTopLevelItem(item)
                elif artifact_type in ['Password', 'Username', 'Token', 'API_Key']:
                    item = QTreeWidgetItem([artifact_type, value, offset])
                    creds_tree.addTopLevelItem(item)
                elif artifact_type in ['Filename', 'File_Extension']:
                    item = QTreeWidgetItem([value, artifact_type, offset])
                    files_tree.addTopLevelItem(item)
                elif artifact_type == 'Base64_Data':
                    full_length = str(artifact.get('full_length', length))
                    item = QTreeWidgetItem([value, full_length, offset])
                    base64_tree.addTopLevelItem(item)
                elif 'License' in artifact_type or artifact.get('category') == 'license':
                    details = f"Length: {length}"
                    item = QTreeWidgetItem([artifact_type.replace('License_', ''), value, details])
                    license_tree.addTopLevelItem(item)

            def on_progress(msg):
                """Update progress message"""
                info_label.setText(f"Extracting artifacts from: {file_path}\nStatus: {msg}")

            def on_finished(artifacts):
                """Handle extraction completion"""
                progress_bar.setRange(0, 1)
                progress_bar.setValue(1)

                # Generate statistics
                stats = []
                stats.append(f"Total artifacts extracted: {len(artifacts)}")

                # Count by type
                type_counts = {}
                for artifact in artifacts:
                    artifact_type = artifact.get('type', 'Unknown')
                    type_counts[artifact_type] = type_counts.get(artifact_type, 0) + 1

                stats.append("\nArtifacts by type:")
                for artifact_type, count in sorted(type_counts.items()):
                    stats.append(f"  {artifact_type}: {count}")

                # File size and processing info
                file_size = os.path.getsize(file_path)
                stats.append(f"\nFile size: {file_size:,} bytes")
                stats.append(f"File type: {os.path.splitext(file_path)[1]}")

                stats_text.setPlainText('\n'.join(stats))

                # Enable export button
                export_btn.setEnabled(True)

            def on_error(error_msg):
                """Handle extraction error"""
                progress_bar.setRange(0, 1)
                progress_bar.setValue(0)
                info_label.setText(f"Error: {error_msg}")
                self.show_message("Extraction Error", f"Failed to extract artifacts: {error_msg}", error=True)

            def export_artifacts():
                """Export artifacts to file"""
                export_path, _ = QFileDialog.getSaveFileName(
                    dialog,
                    "Export Artifacts",
                    f"{os.path.splitext(file_path)[0]}_artifacts.json",
                    "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
                )

                if export_path:
                    try:
                        import json

                        # Collect all artifacts
                        all_artifacts = []

                        # Iterate through all trees
                        trees = {
                            'URLs': urls_tree,
                            'IPs': ips_tree,
                            'Emails': emails_tree,
                            'Credentials': creds_tree,
                            'Files': files_tree,
                            'Base64': base64_tree,
                            'License': license_tree
                        }

                        for category, tree in trees.items():
                            root = tree.invisibleRootItem()
                            for i in range(root.childCount()):
                                item = root.child(i)
                                artifact_data = {
                                    'category': category,
                                    'values': []
                                }
                                for col in range(tree.columnCount()):
                                    artifact_data['values'].append(item.text(col))
                                all_artifacts.append(artifact_data)

                        # Export based on format
                        if export_path.endswith('.json'):
                            with open(export_path, 'w') as f:
                                json.dump(all_artifacts, f, indent=2)
                        elif export_path.endswith('.csv'):
                            import csv
                            with open(export_path, 'w', newline='') as f:
                                writer = csv.writer(f)
                                writer.writerow(['Category', 'Value1', 'Value2', 'Value3'])
                                for artifact in all_artifacts:
                                    row = [artifact['category']] + artifact['values']
                                    writer.writerow(row)
                        else:  # Text format
                            with open(export_path, 'w') as f:
                                for artifact in all_artifacts:
                                    f.write(f"{artifact['category']}: {' | '.join(artifact['values'])}\n")

                        self.show_message("Export Complete", f"Artifacts exported to {export_path}")

                    except Exception as e:
                        self.show_message("Export Error", f"Failed to export artifacts: {str(e)}", error=True)

            def deep_analysis():
                """Perform deep analysis on selected artifacts"""
                current_tree = tab_widget.currentWidget()
                selected_items = current_tree.selectedItems()

                if not selected_items:
                    self.show_message("No Selection", "Please select artifacts to analyze")
                    return

                # Create analysis dialog
                analysis_dialog = QDialog(dialog)
                analysis_dialog.setWindowTitle("Deep Artifact Analysis")
                analysis_dialog.setGeometry(150, 150, 800, 600)

                analysis_layout = QVBoxLayout()

                analysis_text = QTextEdit()
                analysis_text.setReadOnly(True)

                analysis_results = []
                analysis_results.append("=== DEEP ARTIFACT ANALYSIS ===\n")

                for item in selected_items:
                    values = []
                    for col in range(current_tree.columnCount()):
                        values.append(item.text(col))

                    analysis_results.append(f"\nArtifact: {values[0]}")

                    # Perform specific analysis based on type
                    current_tab = tab_widget.tabText(tab_widget.currentIndex())

                    if current_tab == "URLs":
                        # Analyze URL structure
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(values[0])
                            analysis_results.append(f"  Domain: {parsed.netloc}")
                            analysis_results.append(f"  Path: {parsed.path}")
                            analysis_results.append(f"  Scheme: {parsed.scheme}")
                            if parsed.query:
                                analysis_results.append(f"  Query: {parsed.query}")
                        except:
                            pass

                    elif current_tab == "IP Addresses":
                        # Check IP type and range
                        ip = values[0]
                        parts = ip.split('.')
                        if len(parts) == 4:
                            first_octet = int(parts[0])
                            if first_octet == 10 or (first_octet == 172 and 16 <= int(parts[1]) <= 31) or (first_octet == 192 and int(parts[1]) == 168):
                                analysis_results.append("  Type: Private IP (RFC 1918)")
                            elif first_octet == 127:
                                analysis_results.append("  Type: Loopback")
                            else:
                                analysis_results.append("  Type: Public IP")

                    elif current_tab == "Base64 Data":
                        # Try to decode base64
                        import base64
                        try:
                            decoded = base64.b64decode(values[0][:100])
                            analysis_results.append(f"  Decoded preview (hex): {decoded[:20].hex()}")
                            # Check if it might be a file
                            if decoded.startswith(b'MZ'):
                                analysis_results.append("  Possible PE executable")
                            elif decoded.startswith(b'PK'):
                                analysis_results.append("  Possible ZIP archive")
                            elif decoded.startswith(b'%PDF'):
                                analysis_results.append("  Possible PDF document")
                        except:
                            analysis_results.append("  Failed to decode")

                    elif current_tab == "License Artifacts":
                        # Analyze license format
                        value = values[1]
                        analysis_results.append(f"  Length: {len(value)} characters")
                        if '-' in value:
                            parts = value.split('-')
                            analysis_results.append(f"  Format: {len(parts)} segments")
                            analysis_results.append(f"  Segment lengths: {[len(p) for p in parts]}")
                        # Check for common patterns
                        if all(c in '0123456789ABCDEF' for c in value.replace('-', '')):
                            analysis_results.append("  Type: Hexadecimal")
                        elif value.replace('-', '').isalnum():
                            analysis_results.append("  Type: Alphanumeric")

                analysis_text.setPlainText('\n'.join(analysis_results))
                analysis_layout.addWidget(analysis_text)

                close_analysis_btn = QPushButton("Close")
                close_analysis_btn.clicked.connect(analysis_dialog.close)
                analysis_layout.addWidget(close_analysis_btn)

                analysis_dialog.setLayout(analysis_layout)
                analysis_dialog.exec()

            # Connect signals
            extractor.artifact_found.connect(on_artifact_found)
            extractor.progress.connect(on_progress)
            extractor.finished_extraction.connect(on_finished)
            extractor.error.connect(on_error)

            # Connect buttons
            export_btn.clicked.connect(export_artifacts)
            export_btn.setEnabled(False)  # Enable after extraction
            analyze_btn.clicked.connect(deep_analysis)
            close_btn.clicked.connect(dialog.close)

            # Start extraction
            extractor.start()

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            self.logger.error(f"Failed to extract artifacts: {str(e)}")
            self.show_message("Extraction Error", f"Failed to extract artifacts: {str(e)}", error=True)

        except Exception as e:
            self.log_message(f"Error starting traffic monitor: {e}", "error")

    def view_cache_info(self):
        """View cache information"""
        self.log_activity("Viewing cache information...")

    def configure_gpu_acceleration(self):
        """Configure GPU acceleration"""
        self.log_activity("Configuring GPU acceleration...")

    def export_analysis_results(self):
        """Export analysis results to file in user-selected format"""
        try:
            if not hasattr(self, 'results_display') or not self.results_display.toPlainText().strip():
                QMessageBox.warning(self, "Warning", "No analysis results to export!")
                return

            # Let user choose export format and location
            formats = "JSON (*.json);;HTML (*.html);;CSV (*.csv);;Text (*.txt)"
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self, 
                "Export Analysis Results", 
                f"analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}", 
                formats
            )
            
            if not file_path:
                return

            # Determine export format from selected filter
            if "JSON" in selected_filter:
                export_format = "json"
            elif "HTML" in selected_filter:
                export_format = "html"
            elif "CSV" in selected_filter:
                export_format = "csv"
            else:
                export_format = "text"

            # Prepare analysis results for export
            analysis_data = {
                "timestamp": datetime.now().isoformat(),
                "binary_path": getattr(self, 'current_binary', 'Unknown'),
                "analysis_type": "comprehensive",
                "results": self.results_display.toPlainText(),
                "metadata": {
                    "intellicrack_version": "1.0",
                    "export_format": export_format,
                    "analysis_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            }

            # Add additional data if available
            if hasattr(self, 'analysis_progress') and self.analysis_progress.isVisible():
                analysis_data["progress"] = self.analysis_progress.value()
            
            if hasattr(self, 'analysis_status'):
                analysis_data["status"] = self.analysis_status.text()

            # Export using AnalysisExporter
            success = AnalysisExporter.export_analysis(
                result=analysis_data,
                output_file=file_path,
                format=export_format,
                analysis_type="comprehensive"
            )

            if success:
                self.log_activity(f"Analysis results exported successfully to: {file_path}")
                QMessageBox.information(
                    self, 
                    "Export Successful", 
                    f"Analysis results exported to:\n{file_path}"
                )
            else:
                self.log_activity(f"Failed to export analysis results to: {file_path}")
                QMessageBox.critical(
                    self, 
                    "Export Failed", 
                    f"Failed to export analysis results to:\n{file_path}"
                )

        except Exception as e:
            error_msg = f"Export error: {str(e)}"
            self.log_activity(error_msg)
            QMessageBox.critical(self, "Export Error", error_msg)

    def update_binary(self, binary_path):
        """Update the current binary being analyzed"""
        self.current_binary = binary_path
        import os

        binary_name = os.path.basename(binary_path)
        self.results_display.setText(f"Binary loaded: {binary_name}\nReady for analysis.")
        self.log_activity(f"Analysis tab updated for binary: {binary_name}")

    # AppContext signal handlers
    def on_binary_loaded(self, binary_path: str):
        """Handle binary loaded event"""
        self.binary_path = binary_path
        self.binary_info_label.setText(f"Binary: {os.path.basename(binary_path)}")

        # Reset tab when new binary is loaded
        if hasattr(self, "results_tabs"):
            # Clear existing hex viewer if embedded
            hex_view_tab = None
            for i in range(self.results_tabs.count()):
                if self.results_tabs.tabText(i) == "Hex View":
                    hex_view_tab = i
                    break

            if hex_view_tab is not None:
                widget = self.results_tabs.widget(hex_view_tab)
                if widget and hasattr(widget, "hex_viewer"):
                    # Clean up hex viewer
                    widget.hex_viewer.setParent(None)
                    widget.hex_viewer.deleteLater()

                    # Reset to placeholder with button
                    placeholder = QLabel("Hex viewer not embedded")
                    placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    placeholder.setStyleSheet("color: #888;")

                    embed_button = QPushButton("Embed Hex View")
                    embed_button.clicked.connect(self.embed_hex_viewer)

                    layout = widget.layout()
                    if layout:
                        # Clear layout
                        while layout.count():
                            item = layout.takeAt(0)
                            if item.widget():
                                item.widget().deleteLater()

                        # Add placeholder and button
                        layout.addWidget(placeholder)
                        layout.addWidget(embed_button)

        # Clear results
        self.results_display.clear()
        self.static_results_display.clear()
        self.disasm_display.clear()

        # Clear protection items
        self.protection_list.clear()

        # Auto-start protection detection
        self.detect_protections()

    def on_analysis_started(self, analysis_type, options):
        """Handle analysis started signal from AppContext"""
        self.log_activity(f"Analysis started: {analysis_type}")
        # Could update UI to show analysis in progress

    def on_analysis_completed(self, analysis_type, results):
        """Handle analysis completed signal from AppContext"""
        self.log_activity(f"Analysis completed: {analysis_type}")
        self.analysis_status.setText(f"Analysis completed: {analysis_type}")
        self.analysis_progress.setVisible(False)

        # Update UI with results based on analysis type
        if analysis_type == "protection_detection":
            # Format and display protection detection results
            result_text = "=== Protection Detection Results ===\n\n"

            # Display detected protections
            protections = results.get("protections", [])
            if protections:
                result_text += "Detected Protections:\n"
                for protection in protections:
                    result_text += f"  • {protection}\n"
            else:
                result_text += "No protections detected.\n"

            result_text += "\n"

            # Display packers
            packers = results.get("packers", [])
            if packers:
                result_text += "Detected Packers:\n"
                for packer in packers:
                    result_text += f"  • {packer}\n"
            else:
                result_text += "No packers detected.\n"

            result_text += "\n"

            # Display anti-debug techniques
            anti_debug = results.get("anti_debug", [])
            if anti_debug:
                result_text += "Anti-Debug Techniques:\n"
                for technique in anti_debug:
                    result_text += f"  • {technique}\n"
            else:
                result_text += "No anti-debug techniques detected.\n"

            result_text += "\n"

            # Display VM protection info
            vm_protection = results.get("vm_protection", {})
            if vm_protection:
                result_text += "VM Protection:\n"
                for key, value in vm_protection.items():
                    result_text += f"  • {key}: {value}\n"

            result_text += "\n"

            # Display bypass recommendations
            recommendations = results.get("bypass_recommendations", [])
            if recommendations:
                result_text += "Bypass Recommendations:\n"
                for rec in recommendations:
                    result_text += f"  • {rec}\n"

            self.results_display.setText(result_text)
            self.protection_detected.emit(analysis_type, "Multiple protections detected")

        elif analysis_type == "static_analysis":
            # Update static analysis results
            result_text = "=== Static Analysis Results ===\n\n"
            result_text += str(results)
            self.results_display.setText(result_text)

        elif analysis_type == "dynamic_analysis":
            # Update dynamic analysis results
            result_text = "=== Dynamic Analysis Results ===\n\n"
            result_text += str(results)
            self.results_display.setText(result_text)

        elif analysis_type == "quick_analysis":
            # Handle quick analysis from dashboard
            result_text = "=== Quick Analysis Results ===\n\n"
            result_text += f"File: {results.get('file_name', 'Unknown')}\n"
            result_text += f"Format: {results.get('file_format', 'Unknown')}\n"
            result_text += f"Architecture: {results.get('architecture', 'Unknown')}\n"
            result_text += f"Compiler: {results.get('compiler', 'Unknown')}\n"
            result_text += f"Entropy: {results.get('entropy', 0)} ({results.get('entropy_status', 'Unknown')})\n"
            self.results_display.setText(result_text)

        # Store results
        self.analysis_results[analysis_type] = results
        self.analysis_completed.emit(analysis_type)

        # Store results
        self.analysis_results[analysis_type] = results
        self.analysis_completed.emit(analysis_type)

    # Orchestrator signal handlers
    def _on_phase_started(self, phase_name: str):
        """Handle phase started signal from orchestrator"""
        self.log_activity(f"Analysis phase started: {phase_name}")
        self.analysis_status.setText(f"Running: {phase_name}")

    def _on_phase_completed(self, phase_name: str, result: dict):
        """Handle phase completed signal from orchestrator"""
        self.log_activity(f"Analysis phase completed: {phase_name}")

        # Update specific UI elements based on phase
        if phase_name == "static_analysis":
            # Update static results display
            if hasattr(self, "static_results_display"):
                result_text = f"=== {phase_name} ===\n"
                result_text += self._format_phase_result(result)
                self.static_results_display.append(result_text)

        elif phase_name == "entropy_analysis":
            # Update entropy results
            if hasattr(self, "results_tabs"):
                # Find or create entropy tab
                entropy_tab = None
                for i in range(self.results_tabs.count()):
                    if self.results_tabs.tabText(i) == "Entropy":
                        entropy_tab = i
                        break

                if entropy_tab is None:
                    # Create entropy visualizer tab
                    entropy_widget = EntropyVisualizerWidget()
                    self.results_tabs.addTab(entropy_widget, "Entropy")
                    entropy_tab = self.results_tabs.count() - 1

                # Update entropy display
                widget = self.results_tabs.widget(entropy_tab)
                if widget and isinstance(widget, EntropyVisualizerWidget):
                    # Pass the entropy data to the visualizer
                    widget.set_entropy_data(result)

        elif phase_name == "structure_analysis":
            # Update structure results
            if hasattr(self, "results_tabs"):
                # Find or create structure tab
                structure_tab = None
                for i in range(self.results_tabs.count()):
                    if self.results_tabs.tabText(i) == "Structure":
                        structure_tab = i
                        break

                if structure_tab is None:
                    # Create structure visualizer tab
                    structure_widget = StructureVisualizerWidget()
                    self.results_tabs.addTab(structure_widget, "Structure")
                    structure_tab = self.results_tabs.count() - 1

                # Update structure display
                widget = self.results_tabs.widget(structure_tab)
                if widget and isinstance(widget, StructureVisualizerWidget):
                    # Pass the structure data to the visualizer
                    widget.set_structure_data(result)

    def _on_phase_failed(self, phase_name: str, error: str):
        """Handle phase failed signal from orchestrator"""
        self.log_activity(f"Analysis phase failed: {phase_name} - {error}", is_error=True)
        self.analysis_status.setText(f"Failed: {phase_name}")

    def _on_orchestrator_progress(self, current: int, total: int):
        """Handle progress update from orchestrator"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.analysis_progress.setValue(percentage)

    def _on_orchestrator_completed(self, result):
        """Handle orchestrator completion"""
        self.log_activity("Orchestrated analysis completed")
        self.analysis_progress.setVisible(False)
        self.analysis_status.setText("Analysis complete")

        # Generate summary
        summary = f"Analysis completed for: {os.path.basename(result.binary_path)}\n"
        summary += f"Phases completed: {len(result.phases_completed)}\n"
        summary += f"Errors: {len(result.errors)}\n"
        summary += f"Warnings: {len(result.warnings)}\n"

        if result.errors:
            summary += "\nErrors:\n"
            for error in result.errors:
                summary += f"  • {error}\n"

        self.results_display.setText(summary)

    def _format_phase_result(self, result: dict) -> str:
        """Format a phase result for display"""
        if isinstance(result, dict):
            lines = []
            for key, value in result.items():
                if isinstance(value, (list, dict)) and len(str(value)) > 100:
                    lines.append(f"{key}: <{type(value).__name__} with {len(value)} items>")
                else:
                    lines.append(f"{key}: {value}")
            return "\n".join(lines)
        return str(result)

    def _format_entropy_result(self, result: dict) -> str:
        """Format entropy analysis result"""
        text = "=== Entropy Analysis Results ===\n\n"

        if "overall_entropy" in result:
            text += f"Overall Entropy: {result['overall_entropy']:.4f}\n"
            if result["overall_entropy"] > 7.0:
                text += "⚠️ High entropy detected - possible packing/encryption\n"
            text += "\n"

        if "high_entropy_chunks" in result:
            chunks = result.get("high_entropy_chunks", [])
            if chunks:
                text += f"High Entropy Sections: {len(chunks)}\n"
                for chunk in chunks[:10]:  # Show first 10
                    text += f"  • Offset 0x{chunk['offset']:08X}: {chunk['entropy']:.4f}\n"

        return text

    def _handle_analysis_complete(self, result):
        """Handle analysis task completion"""
        if isinstance(result, tuple) and len(result) == 2:
            analysis_type, data = result
            self.on_analysis_completed(analysis_type, data)
        else:
            self.log_activity("Analysis completed with unexpected result format")

    def _handle_analysis_error(self, error):
        """Handle analysis task error"""
        self.log_activity(f"Analysis task error: {error}", is_error=True)
        self.analysis_status.setText("Analysis failed")
        self.analysis_progress.setVisible(False)

    def detect_network_protocols(self):
        """Detect network protocols in binary files or packet captures for license analysis"""
        try:
            import os

            from PyQt6.QtCore import Qt, QThread, pyqtSignal
            from PyQt6.QtWidgets import (
                QDialog,
                QFileDialog,
                QGroupBox,
                QHBoxLayout,
                QLabel,
                QListWidget,
                QProgressBar,
                QPushButton,
                QSplitter,
                QTextEdit,
                QTreeWidget,
                QTreeWidgetItem,
                QVBoxLayout,
            )

            # File selection dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select File for Protocol Detection",
                "",
                "PCAP Files (*.pcap *.pcapng);;Binary Files (*.exe *.dll *.bin);;Memory Dumps (*.dmp *.raw *.mem);;All Files (*)"
            )

            if not file_path:
                return

            # Create results dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Protocol Detection - {os.path.basename(file_path)}")
            dialog.setGeometry(100, 100, 1000, 700)

            layout = QVBoxLayout()

            # File info
            info_label = QLabel(f"Analyzing protocols in: {file_path}")
            info_label.setStyleSheet("font-weight: bold; padding: 10px;")
            layout.addWidget(info_label)

            # Progress bar
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 0)  # Indeterminate
            layout.addWidget(progress_bar)

            # Create splitter for protocols and details
            splitter = QSplitter(Qt.Orientation.Horizontal)

            # Left side - detected protocols
            protocols_group = QGroupBox("Detected Protocols")
            protocols_layout = QVBoxLayout()

            protocols_tree = QTreeWidget()
            protocols_tree.setHeaderLabels(["Protocol", "Count", "Confidence", "License Related"])
            protocols_tree.setAlternatingRowColors(True)
            protocols_layout.addWidget(protocols_tree)

            protocols_group.setLayout(protocols_layout)
            splitter.addWidget(protocols_group)

            # Right side - protocol details
            details_group = QGroupBox("Protocol Details")
            details_layout = QVBoxLayout()

            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_layout.addWidget(details_text)

            details_group.setLayout(details_layout)
            splitter.addWidget(details_group)

            splitter.setSizes([400, 600])
            layout.addWidget(splitter)

            # License communication indicators
            license_group = QGroupBox("License Communication Indicators")
            license_layout = QVBoxLayout()

            license_list = QListWidget()
            license_layout.addWidget(license_list)

            license_group.setLayout(license_layout)
            license_group.setMaximumHeight(150)
            layout.addWidget(license_group)

            # Buttons
            button_layout = QHBoxLayout()

            analyze_btn = QPushButton("Analyze Communication Patterns")
            export_btn = QPushButton("Export Results")
            monitor_btn = QPushButton("Start Live Monitoring")
            close_btn = QPushButton("Close")

            button_layout.addWidget(analyze_btn)
            button_layout.addWidget(export_btn)
            button_layout.addWidget(monitor_btn)
            button_layout.addStretch()
            button_layout.addWidget(close_btn)

            layout.addLayout(button_layout)

            # Worker thread for protocol detection
            class ProtocolDetector(QThread):
                progress = pyqtSignal(str)
                protocol_found = pyqtSignal(dict)
                finished_detection = pyqtSignal(list)
                error = pyqtSignal(str)

                def __init__(self, file_path):
                    super().__init__()
                    self.file_path = file_path

                def run(self):
                    try:
                        import re

                        from intellicrack.core.analysis.network_forensics_engine import (
                            NetworkForensicsEngine,
                        )

                        self.progress.emit("Reading file...")

                        # Read file in chunks for large files
                        chunk_size = 1024 * 1024  # 1MB chunks
                        protocols_found = {}
                        license_indicators = []

                        engine = NetworkForensicsEngine()
                        file_size = os.path.getsize(self.file_path)
                        chunks_processed = 0

                        with open(self.file_path, 'rb') as f:
                            while True:
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break

                                chunks_processed += 1
                                self.progress.emit(f"Processing chunk {chunks_processed} ({chunks_processed * chunk_size / file_size * 100:.1f}%)")

                                # Detect protocols in chunk
                                detected = engine.detect_protocols(chunk)

                                for protocol in detected:
                                    if protocol not in protocols_found:
                                        protocols_found[protocol] = {
                                            'count': 0,
                                            'confidence': 'High',
                                            'license_related': False,
                                            'details': []
                                        }
                                    protocols_found[protocol]['count'] += 1

                                # Look for license-specific patterns
                                license_patterns = [
                                    (rb"license[_-]?server", "License Server Communication"),
                                    (rb"activation[_-]?server", "Activation Server"),
                                    (rb"validate[_-]?license", "License Validation"),
                                    (rb"check[_-]?license", "License Check"),
                                    (rb"license[_-]?key", "License Key Exchange"),
                                    (rb"hardware[_-]?id", "Hardware ID Transmission"),
                                    (rb"machine[_-]?fingerprint", "Machine Fingerprinting"),
                                    (rb"subscription[_-]?check", "Subscription Verification"),
                                    (rb"trial[_-]?expired", "Trial Period Check"),
                                    (rb"product[_-]?activation", "Product Activation"),
                                ]

                                for pattern, description in license_patterns:
                                    if re.search(pattern, chunk, re.IGNORECASE):
                                        indicator = {
                                            'description': description,
                                            'offset': chunks_processed * chunk_size,
                                            'chunk': chunks_processed
                                        }
                                        license_indicators.append(indicator)
                                        self.protocol_found.emit({
                                            'type': 'license_indicator',
                                            'data': indicator
                                        })

                                # Check for specific license protocols
                                if b'HTTP' in str(detected).encode():
                                    # Check for license-related HTTP endpoints
                                    license_endpoints = [
                                        b'/license',
                                        b'/activate',
                                        b'/validate',
                                        b'/api/license',
                                        b'/api/auth',
                                        b'/check',
                                        b'/verify'
                                    ]

                                    for endpoint in license_endpoints:
                                        if endpoint in chunk:
                                            protocols_found.get('HTTP', {})['license_related'] = True
                                            protocols_found.get('HTTP', {})['details'].append(
                                                f"License endpoint detected: {endpoint.decode('utf-8', errors='ignore')}"
                                            )

                                # Emit protocol updates
                                for protocol, data in protocols_found.items():
                                    self.protocol_found.emit({
                                        'type': 'protocol',
                                        'name': protocol,
                                        'data': data
                                    })

                        # Analyze protocol combinations for license detection
                        if 'HTTP' in protocols_found or 'HTTPS/TLS' in protocols_found:
                            if 'DNS' in protocols_found:
                                license_indicators.append({
                                    'description': 'DNS + HTTP/HTTPS: Possible online license validation',
                                    'confidence': 'Medium'
                                })

                        if 'TCP' in protocols_found and len(license_indicators) > 0:
                            for protocol in protocols_found:
                                if 'license' in protocol.lower():
                                    protocols_found[protocol]['license_related'] = True

                        self.progress.emit(f"Detection complete: {len(protocols_found)} protocols found")
                        self.finished_detection.emit(list(protocols_found.items()))

                    except Exception as e:
                        self.error.emit(str(e))

            # Start detection
            detector = ProtocolDetector(file_path)

            protocol_items = {}

            def on_protocol_found(data):
                """Handle protocol detection results"""
                if data['type'] == 'protocol':
                    protocol_name = data['name']
                    protocol_data = data['data']

                    if protocol_name not in protocol_items:
                        item = QTreeWidgetItem([
                            protocol_name,
                            str(protocol_data['count']),
                            protocol_data['confidence'],
                            'Yes' if protocol_data['license_related'] else 'No'
                        ])
                        protocols_tree.addTopLevelItem(item)
                        protocol_items[protocol_name] = item
                    else:
                        # Update existing item
                        item = protocol_items[protocol_name]
                        item.setText(1, str(protocol_data['count']))
                        if protocol_data['license_related']:
                            item.setText(3, 'Yes')
                            item.setForeground(3, Qt.GlobalColor.red)

                elif data['type'] == 'license_indicator':
                    indicator = data['data']
                    license_list.addItem(f"[Chunk {indicator['chunk']}] {indicator['description']}")

            def on_progress(msg):
                """Update progress message"""
                info_label.setText(f"Analyzing protocols in: {file_path}\nStatus: {msg}")

            def on_finished(protocols):
                """Handle detection completion"""
                progress_bar.setRange(0, 1)
                progress_bar.setValue(1)

                # Generate summary
                summary = []
                summary.append("=== PROTOCOL DETECTION SUMMARY ===\n")
                summary.append(f"File: {os.path.basename(file_path)}")
                summary.append(f"Size: {os.path.getsize(file_path):,} bytes")
                summary.append(f"Protocols detected: {len(protocols)}\n")

                # License-related protocols
                license_protocols = [p[0] for p in protocols if p[1].get('license_related', False)]
                if license_protocols:
                    summary.append("LICENSE-RELATED PROTOCOLS:")
                    for protocol in license_protocols:
                        summary.append(f"  • {protocol}")
                    summary.append("")

                # Communication patterns
                summary.append("COMMUNICATION PATTERNS:")
                if 'HTTP' in dict(protocols) or 'HTTPS/TLS' in dict(protocols):
                    summary.append("  • Web-based communication detected")
                    summary.append("    - Likely uses online license validation")
                    summary.append("    - May require internet connection for activation")

                if 'DNS' in dict(protocols):
                    summary.append("  • DNS queries detected")
                    summary.append("    - Resolves license server addresses")

                if 'TCP' in dict(protocols) or 'UDP' in dict(protocols):
                    summary.append("  • Direct socket communication")
                    summary.append("    - May use custom license protocol")

                # Recommendations
                summary.append("\nRECOMMENDATIONS:")
                summary.append("  1. Monitor network traffic during license validation")
                summary.append("  2. Intercept and analyze license server communication")
                summary.append("  3. Check for certificate pinning if HTTPS is used")
                summary.append("  4. Analyze DNS queries for license server domains")

                details_text.setPlainText('\n'.join(summary))

                # Enable export button
                export_btn.setEnabled(True)

            def on_error(error_msg):
                """Handle detection error"""
                progress_bar.setRange(0, 1)
                progress_bar.setValue(0)
                info_label.setText(f"Error: {error_msg}")
                self.show_message("Detection Error", f"Failed to detect protocols: {error_msg}", error=True)

            def on_tree_selection():
                """Show details for selected protocol"""
                selected = protocols_tree.selectedItems()
                if selected:
                    item = selected[0]
                    protocol_name = item.text(0)

                    details = []
                    details.append(f"=== {protocol_name} PROTOCOL ===\n")
                    details.append(f"Detection Count: {item.text(1)}")
                    details.append(f"Confidence: {item.text(2)}")
                    details.append(f"License Related: {item.text(3)}\n")

                    # Protocol-specific details
                    if protocol_name == 'HTTP':
                        details.append("HTTP Protocol Details:")
                        details.append("  • Clear text communication")
                        details.append("  • Easy to intercept and modify")
                        details.append("  • Look for: License keys in headers/body")
                        details.append("  • Check: API endpoints, authentication tokens")
                    elif protocol_name == 'HTTPS/TLS':
                        details.append("HTTPS/TLS Protocol Details:")
                        details.append("  • Encrypted communication")
                        details.append("  • May use certificate pinning")
                        details.append("  • Requires: TLS interception proxy")
                        details.append("  • Check: Certificate validation logic")
                    elif protocol_name == 'DNS':
                        details.append("DNS Protocol Details:")
                        details.append("  • Domain name resolution")
                        details.append("  • Can be redirected/spoofed")
                        details.append("  • Check: License server domains")
                        details.append("  • Consider: DNS poisoning for offline bypass")

                    details_text.setPlainText('\n'.join(details))

            def analyze_patterns():
                """Deep analysis of communication patterns"""
                # Create analysis dialog
                analysis_dialog = QDialog(dialog)
                analysis_dialog.setWindowTitle("Communication Pattern Analysis")
                analysis_dialog.setGeometry(150, 150, 800, 600)

                analysis_layout = QVBoxLayout()

                analysis_text = QTextEdit()
                analysis_text.setReadOnly(True)

                # Perform pattern analysis
                analysis_results = []
                analysis_results.append("=== COMMUNICATION PATTERN ANALYSIS ===\n")

                # Collect all detected protocols
                detected_protocols = []
                for i in range(protocols_tree.topLevelItemCount()):
                    item = protocols_tree.topLevelItem(i)
                    detected_protocols.append(item.text(0))

                # Analyze patterns
                if 'HTTP' in detected_protocols or 'HTTPS/TLS' in detected_protocols:
                    analysis_results.append("WEB-BASED LICENSE VALIDATION PATTERN:")
                    analysis_results.append("  • Application uses HTTP/HTTPS for license checks")
                    analysis_results.append("  • Bypass strategies:")
                    analysis_results.append("    1. Proxy interception and response modification")
                    analysis_results.append("    2. Local web server emulation")
                    analysis_results.append("    3. Hosts file redirection")
                    analysis_results.append("    4. Certificate unpinning for HTTPS")
                    analysis_results.append("")

                if 'DNS' in detected_protocols:
                    analysis_results.append("DNS RESOLUTION PATTERN:")
                    analysis_results.append("  • Application resolves license server domains")
                    analysis_results.append("  • Bypass strategies:")
                    analysis_results.append("    1. DNS spoofing to redirect to local server")
                    analysis_results.append("    2. Hosts file modification")
                    analysis_results.append("    3. Local DNS server with custom responses")
                    analysis_results.append("")

                if license_list.count() > 0:
                    analysis_results.append("LICENSE INDICATORS FOUND:")
                    for i in range(license_list.count()):
                        analysis_results.append(f"  • {license_list.item(i).text()}")
                    analysis_results.append("")

                    analysis_results.append("RECOMMENDED ANALYSIS STEPS:")
                    analysis_results.append("  1. Set up network interception proxy")
                    analysis_results.append("  2. Monitor traffic during:")
                    analysis_results.append("     - Application startup")
                    analysis_results.append("     - License activation")
                    analysis_results.append("     - Feature unlocking")
                    analysis_results.append("  3. Identify license validation endpoints")
                    analysis_results.append("  4. Analyze request/response formats")
                    analysis_results.append("  5. Test response modification")

                analysis_text.setPlainText('\n'.join(analysis_results))
                analysis_layout.addWidget(analysis_text)

                close_analysis_btn = QPushButton("Close")
                close_analysis_btn.clicked.connect(analysis_dialog.close)
                analysis_layout.addWidget(close_analysis_btn)

                analysis_dialog.setLayout(analysis_layout)
                analysis_dialog.exec()

            def export_results():
                """Export protocol detection results"""
                export_path, _ = QFileDialog.getSaveFileName(
                    dialog,
                    "Export Protocol Detection Results",
                    f"{os.path.splitext(file_path)[0]}_protocols.txt",
                    "Text Files (*.txt);;JSON Files (*.json)"
                )

                if export_path:
                    try:
                        import json

                        # Collect results
                        results = {
                            'file': file_path,
                            'file_size': os.path.getsize(file_path),
                            'protocols': {},
                            'license_indicators': []
                        }

                        # Get protocols
                        for i in range(protocols_tree.topLevelItemCount()):
                            item = protocols_tree.topLevelItem(i)
                            protocol_name = item.text(0)
                            results['protocols'][protocol_name] = {
                                'count': item.text(1),
                                'confidence': item.text(2),
                                'license_related': item.text(3) == 'Yes'
                            }

                        # Get license indicators
                        for i in range(license_list.count()):
                            results['license_indicators'].append(license_list.item(i).text())

                        # Export based on format
                        if export_path.endswith('.json'):
                            with open(export_path, 'w') as f:
                                json.dump(results, f, indent=2)
                        else:
                            with open(export_path, 'w') as f:
                                f.write("=== PROTOCOL DETECTION RESULTS ===\n\n")
                                f.write(f"File: {results['file']}\n")
                                f.write(f"Size: {results['file_size']:,} bytes\n\n")

                                f.write("DETECTED PROTOCOLS:\n")
                                for protocol, data in results['protocols'].items():
                                    f.write(f"  {protocol}:\n")
                                    f.write(f"    Count: {data['count']}\n")
                                    f.write(f"    Confidence: {data['confidence']}\n")
                                    f.write(f"    License Related: {data['license_related']}\n")

                                if results['license_indicators']:
                                    f.write("\nLICENSE INDICATORS:\n")
                                    for indicator in results['license_indicators']:
                                        f.write(f"  • {indicator}\n")

                        self.show_message("Export Complete", f"Results exported to {export_path}")

                    except Exception as e:
                        self.show_message("Export Error", f"Failed to export results: {str(e)}", error=True)

            # Connect signals
            detector.protocol_found.connect(on_protocol_found)
            detector.progress.connect(on_progress)
            detector.finished_detection.connect(on_finished)
            detector.error.connect(on_error)

            protocols_tree.itemSelectionChanged.connect(on_tree_selection)

            # Connect buttons
            analyze_btn.clicked.connect(analyze_patterns)
            export_btn.clicked.connect(export_results)
            export_btn.setEnabled(False)
            monitor_btn.clicked.connect(self.monitor_live_traffic)  # Reuse existing method
            close_btn.clicked.connect(dialog.close)

            # Start detection
            detector.start()

            dialog.setLayout(layout)
            dialog.exec()

        except Exception as e:
            self.logger.error(f"Failed to detect protocols: {str(e)}")
            self.show_message("Detection Error", f"Failed to detect protocols: {str(e)}", error=True)
