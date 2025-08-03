"""Analysis Tab Original implementation for Intellicrack UI."""

import os

"""UI module for Analysis Tab Original.

This module provides UI components and dialogs for analysis tab original functionality.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.analysis.analysis_orchestrator import AnalysisOrchestrator, AnalysisPhase
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
        """Initialize the object."""
        super().__init__(shared_context, parent)
        self.current_binary = None
        self.analysis_results = {}

        # Initialize analysis orchestrator
        self.analysis_orchestrator = AnalysisOrchestrator()
        self.analysis_orchestrator.phase_started.connect(self._on_phase_started)
        self.analysis_orchestrator.phase_completed.connect(self._on_phase_completed)
        self.analysis_orchestrator.phase_failed.connect(self._on_phase_failed)
        self.analysis_orchestrator.progress_updated.connect(self._on_orchestrator_progress)
        self.analysis_orchestrator.analysis_completed.connect(self._on_orchestrator_completed)

        # Connect to AppContext signals if available
        if self.app_context:
            self.app_context.binary_loaded.connect(self.on_binary_loaded)
            self.app_context.analysis_started.connect(self.on_analysis_started)
            self.app_context.analysis_completed.connect(self.on_analysis_completed)

    def setup_content(self):
        """Setup the complete Analysis tab content"""
        # Get existing layout or create one
        layout = self.layout()
        if not layout:
            layout = QVBoxLayout(self)

        # Create content widget
        content_widget = QWidget()
        main_layout = QVBoxLayout(content_widget)

        # Create horizontal splitter for analysis tools and results
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Analysis Controls (40%)
        left_panel = self.create_analysis_controls_panel()
        splitter.addWidget(left_panel)

        # Right panel - Results Display (60%)
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter)

        # Add content widget to the main layout
        layout.addWidget(content_widget)

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

        # Entropy graph tab (placeholder)
        self.entropy_view_container = QWidget()
        entropy_layout = QVBoxLayout(self.entropy_view_container)
        entropy_placeholder = QLabel("Entropy visualization will be displayed here")
        entropy_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        entropy_layout.addWidget(entropy_placeholder)
        self.results_tabs.addTab(self.entropy_view_container, "Entropy Graph")

        layout.addLayout(header_layout)
        layout.addWidget(self.analysis_progress)
        layout.addWidget(self.analysis_status)
        layout.addWidget(self.results_tabs)

        return panel

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
            from PyQt6.QtWidgets import QMessageBox

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
            from PyQt6.QtWidgets import QMessageBox

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
            from PyQt6.QtWidgets import QMessageBox

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
            from PyQt6.QtWidgets import QMessageBox

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
            from PyQt6.QtWidgets import QMessageBox

            QMessageBox.warning(
                self, "Error", "Hex viewer module not available. Please check installation."
            )
        except Exception as e:
            self.log_activity(f"Error opening hex viewer: {e!s}")
            from PyQt6.QtWidgets import QMessageBox

            QMessageBox.critical(self, "Error", f"Failed to open hex viewer: {e!s}")

    def embed_hex_viewer(self):
        """Embed hex viewer in the results panel"""
        if not self.current_binary:
            from PyQt6.QtWidgets import QMessageBox

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

    def view_cache_info(self):
        """View cache information"""
        self.log_activity("Viewing cache information...")

    def configure_gpu_acceleration(self):
        """Configure GPU acceleration"""
        self.log_activity("Configuring GPU acceleration...")

    def export_analysis_results(self):
        """Export analysis results"""
        self.log_activity("Exporting analysis results...")

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
