from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLabel, 
    QTextEdit, QTabWidget, QCheckBox, QComboBox, QSpinBox,
    QProgressBar, QSplitter, QWidget, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont

from .base_tab import BaseTab

class AnalysisTab(BaseTab):
    """
    Analysis Tab - Comprehensive binary analysis tools including static analysis,
    dynamic analysis, protection detection, and advanced execution engines.
    """
    
    analysis_started = pyqtSignal(str)
    analysis_completed = pyqtSignal(str)
    protection_detected = pyqtSignal(str, str)
    
    def __init__(self, shared_context=None, parent=None):
        super().__init__(shared_context, parent)
        self.current_binary = None
        self.analysis_results = {}
        
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
        self.analysis_depth_combo.addItems(["Quick Scan", "Standard", "Deep Analysis", "Comprehensive"])
        self.analysis_depth_combo.setCurrentText("Standard")
        
        depth_layout.addWidget(QLabel("Depth Level:"))
        depth_layout.addWidget(self.analysis_depth_combo)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        start_static_btn = QPushButton("Start Static Analysis")
        start_static_btn.clicked.connect(self.start_static_analysis)
        
        view_disasm_btn = QPushButton("View Disassembly")
        view_disasm_btn.clicked.connect(self.view_disassembly)
        
        controls_layout.addWidget(start_static_btn)
        controls_layout.addWidget(view_disasm_btn)
        
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
        
        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setText("No analysis results available. Select a binary and start analysis.")
        
        layout.addLayout(header_layout)
        layout.addWidget(self.analysis_progress)
        layout.addWidget(self.analysis_status)
        layout.addWidget(self.results_display)
        
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
        self.log_activity("Starting static analysis...")
        self.analysis_status.setText("Running static analysis...")
        self.analysis_started.emit("static")
        
    def detect_protections(self):
        """Detect binary protections"""
        self.log_activity("Detecting protections...")
        self.analysis_status.setText("Detecting protections...")
        
    def start_dynamic_monitoring(self):
        """Start dynamic monitoring"""
        self.log_activity("Starting dynamic monitoring...")
        self.analysis_status.setText("Starting dynamic monitoring...")
        
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
        
    def view_protection_info(self):
        """View detailed protection information"""
        self.log_activity("Viewing protection information...")
        
    def attach_to_process(self):
        """Attach to running process for dynamic analysis"""
        self.log_activity("Attaching to process...")
        
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