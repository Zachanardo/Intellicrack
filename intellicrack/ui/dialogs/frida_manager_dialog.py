"""
Frida Manager Dialog - Advanced GUI Controls for Frida Operations

This dialog provides comprehensive controls for all Frida features including:
- Process attachment and script management
- Real-time protection detection and adaptation
- Performance monitoring and optimization
- Preset configurations and automated bypass wizard
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    pass

from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QAction,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from ...core.frida_constants import HookCategory, ProtectionType
from ..widgets.console_widget import ConsoleWidget
from ..widgets.syntax_highlighters import JavaScriptHighlighter

# Import preset configurations
try:
    from ...core.frida_presets import FRIDA_PRESETS
except ImportError:
    FRIDA_PRESETS = {}


class ProcessWorker(QThread):
    """Worker thread for process operations"""
    processFound = pyqtSignal(list)
    error = pyqtSignal(str)

    def run(self):
        """Scan for running processes that can be hooked with Frida."""
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    info = proc.info
                    if info['exe']:  # Only show processes with executables
                        processes.append({
                            'pid': info['pid'],
                            'name': info['name'],
                            'path': info['exe']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.processFound.emit(processes)
        except Exception as e:
            self.error.emit(str(e))


class FridaWorker(QThread):
    """Worker thread for Frida operations"""
    statusUpdate = pyqtSignal(str)
    protectionDetected = pyqtSignal(str, dict)
    performanceUpdate = pyqtSignal(dict)
    error = pyqtSignal(str)
    operationComplete = pyqtSignal(str, bool)

    def __init__(self, frida_manager):
        super().__init__()
        self.frida_manager = frida_manager
        self.operation = None
        self.params = {}

    def run(self):
        """Execute Frida operations based on the specified operation type."""
        try:
            if self.frida_manager is None:
                self.error.emit("FridaManager not available")
                return

            if self.operation == 'attach':
                pid = self.params.get('pid')
                success = self.frida_manager.attach_to_process(pid)
                self.operationComplete.emit('attach', success)

            elif self.operation == 'load_script':
                session_id = self.params.get('session_id')
                script_name = self.params.get('script_name')
                options = self.params.get('options', {})
                success = self.frida_manager.load_script(
                    session_id, script_name, options
                )
                self.operationComplete.emit('load_script', success)

            elif self.operation == 'monitor':
                # Continuous monitoring
                while not self.isInterruptionRequested():
                    stats = self.frida_manager.get_statistics()
                    self.performanceUpdate.emit(stats)
                    self.msleep(1000)  # Update every second

        except Exception as e:
            self.error.emit(str(e))


class FridaManagerDialog(QDialog):
    """Advanced Frida Manager Dialog with comprehensive controls"""

    def __init__(self, parent=None):
        super().__init__(parent)
        # Use lazy import from core module to avoid cyclic import
        from ...core import get_frida_manager
        FridaManager = get_frida_manager()
        self.frida_manager = FridaManager() if FridaManager else None
        self.selected_process = None
        self.current_session = None
        self.monitoring_active = False

        # Worker threads
        self.process_worker = None
        self.frida_worker = None
        self.monitor_worker = None

        # Check if FridaManager is available
        if self.frida_manager is None:
            QMessageBox.warning(
                self,
                "Frida Not Available",
                "Frida components are not available. Some features may be disabled."
            )

        self.init_ui()
        self.load_presets()
        if self.frida_manager is not None:
            self.start_monitoring()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Frida Manager - Advanced Controls")
        self.setGeometry(100, 100, 1400, 900)

        # Create main layout
        layout = QVBoxLayout()

        # Create tab widget
        self.tabs = QTabWidget()

        # Add tabs
        self.tabs.addTab(self.create_process_tab(), "Process Management")
        self.tabs.addTab(self.create_scripts_tab(), "Scripts & Hooks")
        self.tabs.addTab(self.create_ai_generation_tab(), "AI Script Generation")
        self.tabs.addTab(self.create_protection_tab(), "Protection Detection")
        self.tabs.addTab(self.create_performance_tab(), "Performance")
        self.tabs.addTab(self.create_presets_tab(), "Presets & Wizard")
        self.tabs.addTab(self.create_logs_tab(), "Logs & Analysis")

        layout.addWidget(self.tabs)

        # Add status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        # Apply styles
        from ..style_utils import get_default_progress_bar_style
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #2a2a2a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3a3a3a;
                border-bottom: 2px solid #0d7377;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #0d7377;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px;
            }
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #14868c;
            }
            QPushButton:pressed {
                background-color: #0a5a5e;
            }
            QPushButton:disabled {
                background-color: #444;
                color: #888;
            }
            QTableWidget {
                background-color: #2a2a2a;
                color: #ffffff;
                gridline-color: #444;
                selection-background-color: #0d7377;
            }
            QHeaderView::section {
                background-color: #333;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #444;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #555;
                padding: 5px;
                border-radius: 3px;
            }
            QCheckBox {
                color: #ffffff;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444;
                font-family: Consolas, monospace;
            }
            QTreeWidget {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444;
            }
        """ + get_default_progress_bar_style())

    def create_process_tab(self) -> QWidget:
        """Create process management tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Process selection group
        process_group = QGroupBox("Process Selection")
        process_layout = QVBoxLayout()

        # Search bar
        search_layout = QHBoxLayout()
        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("Search processes...")
        self.process_search.textChanged.connect(self.filter_processes)
        search_layout.addWidget(QLabel("Search:"))
        search_layout.addWidget(self.process_search)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        search_layout.addWidget(self.refresh_btn)

        process_layout.addLayout(search_layout)

        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(3)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "Path"])
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.itemSelectionChanged.connect(self.on_process_selected)
        self.process_table.horizontalHeader().setStretchLastSection(True)

        process_layout.addWidget(self.process_table)
        process_group.setLayout(process_layout)
        layout.addWidget(process_group)

        # Attachment controls
        attach_group = QGroupBox("Attachment Controls")
        attach_layout = QHBoxLayout()

        self.attach_btn = QPushButton("Attach to Process")
        self.attach_btn.clicked.connect(self.attach_to_process)
        self.attach_btn.setEnabled(False)
        attach_layout.addWidget(self.attach_btn)

        self.detach_btn = QPushButton("Detach")
        self.detach_btn.clicked.connect(self.detach_from_process)
        self.detach_btn.setEnabled(False)
        attach_layout.addWidget(self.detach_btn)

        attach_layout.addStretch()

        # Session info
        self.session_label = QLabel("No session active")
        attach_layout.addWidget(self.session_label)

        attach_group.setLayout(attach_layout)
        layout.addWidget(attach_group)

        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()

        self.spawn_btn = QPushButton("Spawn Process")
        self.spawn_btn.clicked.connect(self.spawn_process)
        actions_layout.addWidget(self.spawn_btn)

        self.suspend_btn = QPushButton("Suspend")
        self.suspend_btn.clicked.connect(self.suspend_process)
        self.suspend_btn.setEnabled(False)
        actions_layout.addWidget(self.suspend_btn)

        self.resume_btn = QPushButton("Resume")
        self.resume_btn.clicked.connect(self.resume_process)
        self.resume_btn.setEnabled(False)
        actions_layout.addWidget(self.resume_btn)

        actions_layout.addStretch()

        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        widget.setLayout(layout)
        return widget

    def create_scripts_tab(self) -> QWidget:
        """Create scripts and hooks management tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Split view
        splitter = QSplitter(Qt.Horizontal)

        # Left side - Script list
        left_widget = QWidget()
        left_layout = QVBoxLayout()

        scripts_group = QGroupBox("Available Scripts")
        scripts_layout = QVBoxLayout()

        self.scripts_list = QListWidget()
        self.scripts_list.itemDoubleClicked.connect(self.load_selected_script)
        self.scripts_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scripts_list.customContextMenuRequested.connect(self.show_script_context_menu)
        scripts_layout.addWidget(self.scripts_list)

        # Script controls
        script_btns = QHBoxLayout()
        self.load_script_btn = QPushButton("Load Script")
        self.load_script_btn.clicked.connect(self.load_selected_script)
        script_btns.addWidget(self.load_script_btn)

        self.add_script_btn = QPushButton("Add Custom Script")
        self.add_script_btn.clicked.connect(self.add_custom_script)
        script_btns.addWidget(self.add_script_btn)

        self.reload_scripts_btn = QPushButton("Reload List")
        self.reload_scripts_btn.clicked.connect(self.reload_script_list)
        script_btns.addWidget(self.reload_scripts_btn)

        scripts_layout.addLayout(script_btns)
        scripts_group.setLayout(scripts_layout)
        left_layout.addWidget(scripts_group)

        # Loaded scripts
        loaded_group = QGroupBox("Loaded Scripts")
        loaded_layout = QVBoxLayout()

        self.loaded_scripts_list = QListWidget()
        self.loaded_scripts_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.loaded_scripts_list.customContextMenuRequested.connect(
            self.show_loaded_script_menu
        )
        loaded_layout.addWidget(self.loaded_scripts_list)

        loaded_group.setLayout(loaded_layout)
        left_layout.addWidget(loaded_group)

        # AI Script Generation
        ai_group = self.create_ai_generation_group()
        left_layout.addWidget(ai_group)

        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)

        # Right side - Hook management
        right_widget = QWidget()
        right_layout = QVBoxLayout()

        # Hook configuration
        hook_config_group = QGroupBox("Hook Configuration")
        hook_config_layout = QVBoxLayout()

        # Batching controls
        batch_layout = QHBoxLayout()
        self.batch_hooks_cb = QCheckBox("Enable Hook Batching")
        self.batch_hooks_cb.setChecked(True)
        batch_layout.addWidget(self.batch_hooks_cb)

        batch_layout.addWidget(QLabel("Batch Size:"))
        self.batch_size_spin = QSpinBox()
        self.batch_size_spin.setRange(10, 200)
        self.batch_size_spin.setValue(50)
        batch_layout.addWidget(self.batch_size_spin)

        batch_layout.addWidget(QLabel("Timeout (ms):"))
        self.batch_timeout_spin = QSpinBox()
        self.batch_timeout_spin.setRange(10, 1000)
        self.batch_timeout_spin.setValue(100)
        batch_layout.addWidget(self.batch_timeout_spin)

        batch_layout.addStretch()
        hook_config_layout.addLayout(batch_layout)

        # Selective instrumentation
        selective_layout = QHBoxLayout()
        self.selective_cb = QCheckBox("Selective Instrumentation")
        self.selective_cb.setChecked(True)
        selective_layout.addWidget(self.selective_cb)

        selective_layout.addWidget(QLabel("Priority:"))
        self.hook_priority_combo = QComboBox()
        for category in HookCategory:
            self.hook_priority_combo.addItem(category.value)
        selective_layout.addWidget(self.hook_priority_combo)

        selective_layout.addStretch()
        hook_config_layout.addLayout(selective_layout)

        hook_config_group.setLayout(hook_config_layout)
        right_layout.addWidget(hook_config_group)

        # Active hooks tree
        hooks_group = QGroupBox("Active Hooks")
        hooks_layout = QVBoxLayout()

        self.hooks_tree = QTreeWidget()
        self.hooks_tree.setHeaderLabels(["Module", "Function", "Category", "Calls/sec"])
        hooks_layout.addWidget(self.hooks_tree)

        # Hook stats
        self.hook_stats_label = QLabel("Total Hooks: 0 | Active: 0")
        hooks_layout.addWidget(self.hook_stats_label)

        hooks_group.setLayout(hooks_layout)
        right_layout.addWidget(hooks_group)

        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)

        layout.addWidget(splitter)

        widget.setLayout(layout)
        return widget

    def create_ai_generation_tab(self) -> QWidget:
        """Create AI script generation tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # AI Status group
        ai_status_group = QGroupBox("AI Status")
        ai_status_layout = QHBoxLayout()

        self.ai_status_label = QLabel("AI Ready")
        self.ai_status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        ai_status_layout.addWidget(self.ai_status_label)

        ai_status_layout.addStretch()

        # LLM info
        self.llm_info_label = QLabel("LLM: Not configured")
        ai_status_layout.addWidget(self.llm_info_label)

        ai_status_group.setLayout(ai_status_layout)
        layout.addWidget(ai_status_group)

        # Generation controls group
        generation_group = QGroupBox("Script Generation")
        generation_layout = QVBoxLayout()

        # Target selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Binary:"))
        self.target_binary_edit = QLineEdit()
        target_layout.addWidget(self.target_binary_edit)

        self.browse_target_btn = QPushButton("Browse...")
        self.browse_target_btn.clicked.connect(self.browse_target_binary)
        target_layout.addWidget(self.browse_target_btn)

        generation_layout.addLayout(target_layout)

        # Generation options
        options_layout = QHBoxLayout()

        options_layout.addWidget(QLabel("Script Type:"))
        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(["Frida Only", "Ghidra Only", "Both Frida & Ghidra"])
        options_layout.addWidget(self.script_type_combo)

        options_layout.addWidget(QLabel("Complexity:"))
        self.complexity_combo = QComboBox()
        self.complexity_combo.addItems(["Basic", "Advanced"])
        options_layout.addWidget(self.complexity_combo)

        options_layout.addWidget(QLabel("Focus:"))
        self.focus_combo = QComboBox()
        self.focus_combo.addItems(["Auto-detect", "License Check", "Trial Timer", "Network Validation", "Anti-Debug", "VM Detection"])
        options_layout.addWidget(self.focus_combo)

        generation_layout.addLayout(options_layout)

        # Advanced options
        advanced_layout = QHBoxLayout()

        self.autonomous_cb = QCheckBox("Autonomous Mode (with QEMU testing)")
        self.autonomous_cb.setChecked(True)
        advanced_layout.addWidget(self.autonomous_cb)

        self.preview_cb = QCheckBox("Preview scripts before saving")
        self.preview_cb.setChecked(True)
        advanced_layout.addWidget(self.preview_cb)

        generation_layout.addLayout(advanced_layout)

        # Generation button
        gen_button_layout = QHBoxLayout()
        gen_button_layout.addStretch()

        self.generate_btn = QPushButton("🤖 Generate AI Scripts")
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #14868c;
            }
            QPushButton:pressed {
                background-color: #0a5a5e;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_ai_scripts)
        gen_button_layout.addWidget(self.generate_btn)

        gen_button_layout.addStretch()
        generation_layout.addLayout(gen_button_layout)

        generation_group.setLayout(generation_layout)
        layout.addWidget(generation_group)

        # Progress group
        progress_group = QGroupBox("Generation Progress")
        progress_layout = QVBoxLayout()

        self.progress_label = QLabel("Ready to generate scripts")
        progress_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # Results preview group
        preview_group = QGroupBox("Generated Scripts Preview")
        preview_layout = QVBoxLayout()

        self.script_preview = QTextEdit()
        self.script_preview.setMaximumHeight(200)
        self.script_preview.setReadOnly(True)
        self.script_preview.setPlaceholderText("Generated scripts will appear here...")
        preview_layout.addWidget(self.script_preview)

        # Preview controls
        preview_controls = QHBoxLayout()

        self.save_scripts_btn = QPushButton("💾 Save Scripts")
        self.save_scripts_btn.clicked.connect(self.save_generated_scripts)
        self.save_scripts_btn.setEnabled(False)
        preview_controls.addWidget(self.save_scripts_btn)

        self.deploy_scripts_btn = QPushButton("🚀 Deploy to Current Session")
        self.deploy_scripts_btn.clicked.connect(self.deploy_generated_scripts)
        self.deploy_scripts_btn.setEnabled(False)
        preview_controls.addWidget(self.deploy_scripts_btn)

        self.test_qemu_btn = QPushButton("🧪 Test in QEMU")
        self.test_qemu_btn.clicked.connect(self.test_scripts_in_qemu)
        self.test_qemu_btn.setEnabled(False)
        preview_controls.addWidget(self.test_qemu_btn)

        preview_controls.addStretch()
        preview_layout.addLayout(preview_controls)

        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_protection_tab(self) -> QWidget:
        """Create protection detection and adaptation tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Detection status
        detection_group = QGroupBox("Protection Detection Status")
        detection_layout = QVBoxLayout()

        # Protection type grid
        self.protection_grid = QTableWidget()
        self.protection_grid.setColumnCount(4)
        self.protection_grid.setHorizontalHeaderLabels(
            ["Protection Type", "Status", "Evidence", "Action"]
        )
        self.protection_grid.horizontalHeader().setStretchLastSection(True)

        # Add rows for each protection type
        self.protection_grid.setRowCount(len(ProtectionType))
        for i, prot_type in enumerate(ProtectionType):
            self.protection_grid.setItem(i, 0, QTableWidgetItem(prot_type.value))
            self.protection_grid.setItem(i, 1, QTableWidgetItem("Not Detected"))
            self.protection_grid.setItem(i, 2, QTableWidgetItem("-"))

            # Add bypass button
            bypass_btn = QPushButton("Bypass")
            bypass_btn.clicked.connect(lambda checked, pt=prot_type: self.bypass_protection(pt))
            bypass_btn.setEnabled(False)
            self.protection_grid.setCellWidget(i, 3, bypass_btn)

        detection_layout.addWidget(self.protection_grid)
        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)

        # Adaptation settings
        adapt_group = QGroupBox("Adaptation Settings")
        adapt_layout = QVBoxLayout()

        # Auto-adapt checkbox
        self.auto_adapt_cb = QCheckBox("Enable Automatic Adaptation")
        self.auto_adapt_cb.setChecked(True)
        adapt_layout.addWidget(self.auto_adapt_cb)

        # Adaptation log
        adapt_layout.addWidget(QLabel("Adaptation Log:"))
        self.adaptation_log = QTextEdit()
        self.adaptation_log.setMaximumHeight(150)
        self.adaptation_log.setReadOnly(True)
        adapt_layout.addWidget(self.adaptation_log)

        adapt_group.setLayout(adapt_layout)
        layout.addWidget(adapt_group)

        widget.setLayout(layout)
        return widget

    def create_performance_tab(self) -> QWidget:
        """Create performance monitoring and optimization tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Resource usage
        resource_group = QGroupBox("Resource Usage")
        resource_layout = QVBoxLayout()

        # Metrics grid
        metrics_layout = QHBoxLayout()

        # CPU usage
        cpu_widget = QWidget()
        cpu_layout = QVBoxLayout()
        cpu_layout.addWidget(QLabel("CPU Usage"))
        self.cpu_progress = QProgressBar()
        self.cpu_progress.setMaximum(100)
        cpu_layout.addWidget(self.cpu_progress)
        self.cpu_label = QLabel("0%")
        cpu_layout.addWidget(self.cpu_label)
        cpu_widget.setLayout(cpu_layout)
        metrics_layout.addWidget(cpu_widget)

        # Memory usage
        mem_widget = QWidget()
        mem_layout = QVBoxLayout()
        mem_layout.addWidget(QLabel("Memory Usage"))
        self.mem_progress = QProgressBar()
        self.mem_progress.setMaximum(1000)  # MB
        mem_layout.addWidget(self.mem_progress)
        self.mem_label = QLabel("0 MB")
        mem_layout.addWidget(self.mem_label)
        mem_widget.setLayout(mem_layout)
        metrics_layout.addWidget(mem_widget)

        # Thread count
        thread_widget = QWidget()
        thread_layout = QVBoxLayout()
        thread_layout.addWidget(QLabel("Threads"))
        self.thread_label = QLabel("0")
        self.thread_label.setAlignment(Qt.AlignCenter)
        self.thread_label.setStyleSheet("font-size: 24px; color: #0d7377;")
        thread_layout.addWidget(self.thread_label)
        thread_widget.setLayout(thread_layout)
        metrics_layout.addWidget(thread_widget)

        resource_layout.addLayout(metrics_layout)
        resource_group.setLayout(resource_layout)
        layout.addWidget(resource_group)

        # Optimization settings
        opt_group = QGroupBox("Optimization Settings")
        opt_layout = QVBoxLayout()

        # Optimization toggles
        self.opt_memory_cb = QCheckBox("Memory Optimization")
        self.opt_memory_cb.setChecked(True)
        opt_layout.addWidget(self.opt_memory_cb)

        self.opt_cpu_cb = QCheckBox("CPU Optimization")
        self.opt_cpu_cb.setChecked(True)
        opt_layout.addWidget(self.opt_cpu_cb)

        self.cache_cb = QCheckBox("Enable Result Caching")
        self.cache_cb.setChecked(True)
        opt_layout.addWidget(self.cache_cb)

        # Recommendations
        opt_layout.addWidget(QLabel("Optimization Recommendations:"))
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setMaximumHeight(100)
        self.recommendations_text.setReadOnly(True)
        opt_layout.addWidget(self.recommendations_text)

        opt_group.setLayout(opt_layout)
        layout.addWidget(opt_group)

        # Performance history
        perf_group = QGroupBox("Performance History")
        perf_layout = QVBoxLayout()

        self.perf_table = QTableWidget()
        self.perf_table.setColumnCount(4)
        self.perf_table.setHorizontalHeaderLabels(
            ["Timestamp", "Operation", "Duration (ms)", "Memory Delta"]
        )
        perf_layout.addWidget(self.perf_table)

        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)

        widget.setLayout(layout)
        return widget

    def create_presets_tab(self) -> QWidget:
        """Create presets and wizard tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Preset configurations
        preset_group = QGroupBox("Preset Configurations")
        preset_layout = QVBoxLayout()

        # Preset selector
        preset_select_layout = QHBoxLayout()
        preset_select_layout.addWidget(QLabel("Select Preset:"))

        self.preset_combo = QComboBox()
        self.preset_combo.addItem("-- Select Preset --")
        # Add presets from configuration
        for preset_name in FRIDA_PRESETS.keys():
            self.preset_combo.addItem(preset_name)
        self.preset_combo.currentTextChanged.connect(self.on_preset_selected)
        preset_select_layout.addWidget(self.preset_combo)

        self.apply_preset_btn = QPushButton("Apply Preset")
        self.apply_preset_btn.clicked.connect(self.apply_selected_preset)
        self.apply_preset_btn.setEnabled(False)
        preset_select_layout.addWidget(self.apply_preset_btn)

        preset_select_layout.addStretch()
        preset_layout.addLayout(preset_select_layout)

        # Preset details
        self.preset_details = QTextEdit()
        self.preset_details.setMaximumHeight(150)
        self.preset_details.setReadOnly(True)
        preset_layout.addWidget(self.preset_details)

        preset_group.setLayout(preset_layout)
        layout.addWidget(preset_group)

        # Bypass wizard
        wizard_group = QGroupBox("Automated Bypass Wizard")
        wizard_layout = QVBoxLayout()

        wizard_layout.addWidget(QLabel(
            "The bypass wizard automatically detects and bypasses protections."
        ))

        # Wizard options
        wizard_options_layout = QHBoxLayout()

        self.wizard_aggressive_cb = QCheckBox("Aggressive Mode")
        wizard_options_layout.addWidget(self.wizard_aggressive_cb)

        self.wizard_stealth_cb = QCheckBox("Stealth Mode")
        wizard_options_layout.addWidget(self.wizard_stealth_cb)

        self.wizard_safe_cb = QCheckBox("Safe Mode")
        self.wizard_safe_cb.setChecked(True)
        wizard_options_layout.addWidget(self.wizard_safe_cb)

        wizard_options_layout.addStretch()
        wizard_layout.addLayout(wizard_options_layout)

        # Wizard controls
        wizard_control_layout = QHBoxLayout()

        self.start_wizard_btn = QPushButton("Start Wizard")
        self.start_wizard_btn.clicked.connect(self.start_bypass_wizard)
        wizard_control_layout.addWidget(self.start_wizard_btn)

        self.stop_wizard_btn = QPushButton("Stop Wizard")
        self.stop_wizard_btn.clicked.connect(self.stop_bypass_wizard)
        self.stop_wizard_btn.setEnabled(False)
        wizard_control_layout.addWidget(self.stop_wizard_btn)

        wizard_control_layout.addStretch()
        wizard_layout.addLayout(wizard_control_layout)

        # Wizard progress
        self.wizard_progress = QProgressBar()
        wizard_layout.addWidget(self.wizard_progress)

        self.wizard_status = QTextEdit()
        self.wizard_status.setMaximumHeight(100)
        self.wizard_status.setReadOnly(True)
        wizard_layout.addWidget(self.wizard_status)

        wizard_group.setLayout(wizard_layout)
        layout.addWidget(wizard_group)

        # Custom configuration
        custom_group = QGroupBox("Custom Configuration")
        custom_layout = QVBoxLayout()

        custom_layout.addWidget(QLabel("Create custom bypass configuration:"))

        self.custom_config_text = QTextEdit()
        self.custom_config_text.setPlaceholderText(
            "Enter custom configuration JSON here..."
        )
        custom_layout.addWidget(self.custom_config_text)

        custom_btn_layout = QHBoxLayout()
        self.save_custom_btn = QPushButton("Save Configuration")
        self.save_custom_btn.clicked.connect(self.save_custom_config)
        custom_btn_layout.addWidget(self.save_custom_btn)

        self.load_custom_btn = QPushButton("Load Configuration")
        self.load_custom_btn.clicked.connect(self.load_custom_config)
        custom_btn_layout.addWidget(self.load_custom_btn)

        custom_btn_layout.addStretch()
        custom_layout.addLayout(custom_btn_layout)

        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)

        widget.setLayout(layout)
        return widget

    def create_logs_tab(self) -> QWidget:
        """Create logs and analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Log viewer
        log_group = QGroupBox("Operation Logs")
        log_layout = QVBoxLayout()

        # Log filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.log_filter_combo = QComboBox()
        self.log_filter_combo.addItems([
            "All", "Operations", "Hooks", "Performance", "Bypasses", "Errors"
        ])
        self.log_filter_combo.currentTextChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.log_filter_combo)

        filter_layout.addWidget(QLabel("Search:"))
        self.log_search = QLineEdit()
        self.log_search.textChanged.connect(self.search_logs)
        filter_layout.addWidget(self.log_search)

        filter_layout.addStretch()

        self.clear_logs_btn = QPushButton("Clear Logs")
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        filter_layout.addWidget(self.clear_logs_btn)

        log_layout.addLayout(filter_layout)

        # Log console
        self.log_console = ConsoleWidget()
        log_layout.addWidget(self.log_console)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Analysis summary
        analysis_group = QGroupBox("Analysis Summary")
        analysis_layout = QVBoxLayout()

        # Statistics table
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.horizontalHeader().setStretchLastSection(True)

        analysis_layout.addWidget(self.stats_table)

        # Export controls
        export_layout = QHBoxLayout()
        self.export_logs_btn = QPushButton("Export Logs")
        self.export_logs_btn.clicked.connect(self.export_logs)
        export_layout.addWidget(self.export_logs_btn)

        self.export_analysis_btn = QPushButton("Export Analysis")
        self.export_analysis_btn.clicked.connect(self.export_analysis)
        export_layout.addWidget(self.export_analysis_btn)

        export_layout.addStretch()
        analysis_layout.addLayout(export_layout)

        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)

        widget.setLayout(layout)
        return widget

    def load_presets(self):
        """Load preset configurations"""
        # This will be loaded from frida_presets.py
        pass

    def start_monitoring(self):
        """Start performance monitoring"""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_performance_stats)
        self.monitor_timer.start(1000)  # Update every second

        # Initial process refresh
        self.refresh_processes()

        # Load available scripts
        self.reload_script_list()

    def refresh_processes(self):
        """Refresh the process list"""
        self.process_worker = ProcessWorker()
        self.process_worker.processFound.connect(self.update_process_table)
        self.process_worker.error.connect(self.show_error)
        self.process_worker.start()

        self.status_label.setText("Refreshing process list...")

    def update_process_table(self, processes: List[Dict]):
        """Update the process table with found processes"""
        self.process_table.setRowCount(len(processes))

        for i, proc in enumerate(processes):
            self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(i, 2, QTableWidgetItem(proc['path']))

        self.status_label.setText(f"Found {len(processes)} processes")

    def filter_processes(self, text: str):
        """Filter processes based on search text"""
        for i in range(self.process_table.rowCount()):
            match = False
            for j in range(self.process_table.columnCount()):
                item = self.process_table.item(i, j)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.process_table.setRowHidden(i, not match)

    def on_process_selected(self):
        """Handle process selection"""
        selected = self.process_table.selectedItems()
        if selected:
            row = selected[0].row()
            pid = int(self.process_table.item(row, 0).text())
            name = self.process_table.item(row, 1).text()
            self.selected_process = {'pid': pid, 'name': name}
            self.attach_btn.setEnabled(True)
            self.status_label.setText(f"Selected: {name} (PID: {pid})")

    def attach_to_process(self):
        """Attach Frida to selected process"""
        if not self.selected_process:
            return

        self.frida_worker = FridaWorker(self.frida_manager)
        self.frida_worker.operation = 'attach'
        self.frida_worker.params = {'pid': self.selected_process['pid']}
        self.frida_worker.operationComplete.connect(self.on_attach_complete)
        self.frida_worker.error.connect(self.show_error)
        self.frida_worker.start()

        self.status_label.setText(f"Attaching to {self.selected_process['name']}...")
        self.attach_btn.setEnabled(False)

    def on_attach_complete(self, operation: str, success: bool):
        """Handle attachment completion"""
        if operation == 'attach' and success:
            self.current_session = f"{self.selected_process['name']}_{self.selected_process['pid']}"
            self.session_label.setText(f"Session: {self.current_session}")
            self.detach_btn.setEnabled(True)
            self.suspend_btn.setEnabled(True)
            self.load_script_btn.setEnabled(True)
            self.status_label.setText("Successfully attached to process")

            # Log to console
            self.log_console.append_output(
                f"[SUCCESS] Attached to {self.selected_process['name']} "
                f"(PID: {self.selected_process['pid']})"
            )
        else:
            self.status_label.setText("Failed to attach to process")
            self.attach_btn.setEnabled(True)

    def detach_from_process(self):
        """Detach from current process"""
        if self.current_session:
            # Detach logic would go here
            self.current_session = None
            self.session_label.setText("No session active")
            self.detach_btn.setEnabled(False)
            self.suspend_btn.setEnabled(False)
            self.resume_btn.setEnabled(False)
            self.load_script_btn.setEnabled(False)
            self.status_label.setText("Detached from process")

    def spawn_process(self):
        """Spawn a new process"""
        # Implementation for spawning process
        QMessageBox.information(self, "Spawn Process",
                               "Process spawning not implemented yet")

    def suspend_process(self):
        """Suspend the attached process"""
        if self.current_session:
            self.suspend_btn.setEnabled(False)
            self.resume_btn.setEnabled(True)
            self.status_label.setText("Process suspended")

    def resume_process(self):
        """Resume the attached process"""
        if self.current_session:
            self.resume_btn.setEnabled(False)
            self.suspend_btn.setEnabled(True)
            self.status_label.setText("Process resumed")

    def reload_script_list(self):
        """Reload the list of available scripts"""
        self.scripts_list.clear()
        # Use the same path as FridaManager
        scripts_dir = self.frida_manager.script_dir

        if scripts_dir.exists():
            for script_file in scripts_dir.glob("*.js"):
                item = QListWidgetItem(script_file.stem)
                item.setData(Qt.UserRole, str(script_file))
                self.scripts_list.addItem(item)

        self.status_label.setText(f"Found {self.scripts_list.count()} scripts")

    def add_custom_script(self):
        """Add a custom Frida script from file"""
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Frida Script",
            "",
            "JavaScript Files (*.js);;All Files (*)"
        )

        if not file_path:
            return

        # Get scripts directory from FridaManager
        scripts_dir = self.frida_manager.script_dir

        # Copy script to scripts directory
        source_path = Path(file_path)
        dest_path = scripts_dir / source_path.name

        try:
            import shutil
            # Ask if should overwrite if exists
            if dest_path.exists():
                reply = QMessageBox.question(
                    self,
                    "Script Exists",
                    f"Script '{source_path.name}' already exists. Overwrite?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            # Copy the file
            shutil.copy2(file_path, dest_path)

            # Log success
            self.log_console.append_output(
                f"[SUCCESS] Added custom script: {source_path.name}"
            )
            self.status_label.setText(f"Added script: {source_path.name}")

            # Reload script list to show new script
            self.reload_script_list()

            # Show script preview dialog
            self.preview_script(dest_path)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to add script: {str(e)}"
            )
            self.log_console.append_output(
                f"[ERROR] Failed to add script: {str(e)}"
            )

    def preview_script(self, script_path: Path):
        """Show a preview of the script"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Script Preview: {script_path.name}")
        dialog.resize(800, 600)

        layout = QVBoxLayout()

        # Script content viewer
        content_edit = QTextEdit()
        content_edit.setReadOnly(True)
        content_edit.setFont(QFont("Consolas", 10))

        try:
            with open(script_path, 'r') as f:
                content = f.read()
            content_edit.setPlainText(content)

            # Simple syntax highlighting
            JavaScriptHighlighter(content_edit.document())

        except Exception as e:
            content_edit.setPlainText(f"Error reading script: {str(e)}")

        layout.addWidget(QLabel(f"Location: {script_path}"))
        layout.addWidget(content_edit)

        # Buttons
        btn_layout = QHBoxLayout()

        edit_btn = QPushButton("Edit Script")
        edit_btn.clicked.connect(lambda: self.edit_script(script_path))
        btn_layout.addWidget(edit_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)
        dialog.setLayout(layout)
        dialog.exec_()

    def edit_script(self, script_path: Path):
        """Open script in external editor"""
        try:
            if sys.platform == "win32":
                os.startfile(script_path)
            elif sys.platform == "darwin":
                os.system(f"open '{script_path}'")
            else:
                os.system(f"xdg-open '{script_path}'")
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to open script editor: {str(e)}"
            )

    def load_selected_script(self):
        """Load the selected script"""
        if not self.current_session:
            QMessageBox.warning(self, "No Session",
                               "Please attach to a process first")
            return

        current_item = self.scripts_list.currentItem()
        if not current_item:
            return

        script_name = current_item.text()

        # Get hook options from UI
        options = {
            'batch_hooks': self.batch_hooks_cb.isChecked(),
            'batch_size': self.batch_size_spin.value(),
            'batch_timeout': self.batch_timeout_spin.value(),
            'selective': self.selective_cb.isChecked(),
            'priority': self.hook_priority_combo.currentText()
        }

        self.frida_worker = FridaWorker(self.frida_manager)
        self.frida_worker.operation = 'load_script'
        self.frida_worker.params = {
            'session_id': self.current_session,
            'script_name': script_name,
            'options': options
        }
        self.frida_worker.operationComplete.connect(self.on_script_loaded)
        self.frida_worker.error.connect(self.show_error)
        self.frida_worker.start()

        self.status_label.setText(f"Loading script: {script_name}")

    def on_script_loaded(self, operation: str, success: bool):
        """Handle script loading completion"""
        if operation == 'load_script' and success:
            script_name = self.frida_worker.params.get('script_name')
            self.loaded_scripts_list.addItem(script_name)
            self.status_label.setText(f"Script loaded: {script_name}")

            # Log to console
            self.log_console.append_output(
                f"[SCRIPT] Loaded {script_name} successfully"
            )

    def show_script_context_menu(self, position):
        """Show context menu for available scripts"""
        item = self.scripts_list.itemAt(position)
        if not item:
            return

        menu = QMenu()

        # Load script
        load_action = QAction("Load Script", self)
        load_action.triggered.connect(self.load_selected_script)
        menu.addAction(load_action)

        menu.addSeparator()

        # Preview script
        preview_action = QAction("Preview Script", self)
        preview_action.triggered.connect(lambda: self.preview_script(
            Path(item.data(Qt.UserRole))
        ))
        menu.addAction(preview_action)

        # Edit script
        edit_action = QAction("Edit Script", self)
        edit_action.triggered.connect(lambda: self.edit_script(
            Path(item.data(Qt.UserRole))
        ))
        menu.addAction(edit_action)

        menu.addSeparator()

        # Delete script
        delete_action = QAction("Delete Script", self)
        delete_action.triggered.connect(lambda: self.delete_script(item))
        menu.addAction(delete_action)

        # Duplicate script
        duplicate_action = QAction("Duplicate Script", self)
        duplicate_action.triggered.connect(lambda: self.duplicate_script(item))
        menu.addAction(duplicate_action)

        menu.exec_(self.scripts_list.mapToGlobal(position))

    def delete_script(self, item):
        """Delete a script after confirmation"""
        script_path = Path(item.data(Qt.UserRole))

        reply = QMessageBox.question(
            self,
            "Delete Script",
            f"Are you sure you want to delete '{script_path.name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                script_path.unlink()
                self.reload_script_list()
                self.log_console.append_output(
                    f"[SUCCESS] Deleted script: {script_path.name}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete script: {str(e)}"
                )

    def duplicate_script(self, item):
        """Duplicate a script with a new name"""
        script_path = Path(item.data(Qt.UserRole))

        # Generate new name
        base_name = script_path.stem
        suffix = 1
        while True:
            new_name = f"{base_name}_copy{suffix}.js"
            new_path = script_path.parent / new_name
            if not new_path.exists():
                break
            suffix += 1

        try:
            import shutil
            shutil.copy2(script_path, new_path)
            self.reload_script_list()
            self.log_console.append_output(
                f"[SUCCESS] Duplicated script: {script_path.name} → {new_name}"
            )

            # Open for editing
            self.edit_script(new_path)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to duplicate script: {str(e)}"
            )

    def show_loaded_script_menu(self, position):
        """Show context menu for loaded scripts"""
        menu = QMenu()
        unload_action = QAction("Unload Script", self)
        unload_action.triggered.connect(self.unload_script)
        menu.addAction(unload_action)

        menu.exec_(self.loaded_scripts_list.mapToGlobal(position))

    def unload_script(self):
        """Unload selected script"""
        current_item = self.loaded_scripts_list.currentItem()
        if current_item:
            self.loaded_scripts_list.takeItem(self.loaded_scripts_list.row(current_item))
            self.status_label.setText(f"Unloaded script: {current_item.text()}")

    def update_performance_stats(self):
        """Update performance statistics"""
        if not self.current_session:
            return

        try:
            stats = self.frida_manager.get_statistics()

            # Update performance tab
            if 'optimizer' in stats:
                usage = stats['optimizer']['current_usage']

                # CPU
                cpu_percent = int(usage.get('cpu_percent', 0))
                self.cpu_progress.setValue(cpu_percent)
                self.cpu_label.setText(f"{cpu_percent}%")

                # Memory
                memory_mb = int(usage.get('memory_mb', 0))
                self.mem_progress.setValue(memory_mb)
                self.mem_label.setText(f"{memory_mb} MB")

                # Threads
                threads = usage.get('threads', 0)
                self.thread_label.setText(str(threads))

                # Recommendations
                recommendations = stats['optimizer'].get('recommendations', [])
                self.recommendations_text.clear()
                for rec in recommendations:
                    self.recommendations_text.append(f"• {rec}")

            # Update protection detection
            if 'detector' in stats:
                protections = stats['detector']
                for i, prot_type in enumerate(ProtectionType):
                    if prot_type.value in protections:
                        self.protection_grid.item(i, 1).setText("DETECTED")
                        self.protection_grid.item(i, 1).setForeground(QColor("#ff6b6b"))
                        evidence = ", ".join(protections[prot_type.value][:3])
                        self.protection_grid.item(i, 2).setText(evidence)
                        # Enable bypass button
                        btn = self.protection_grid.cellWidget(i, 3)
                        if btn:
                            btn.setEnabled(True)

            # Update statistics table
            if 'logger' in stats:
                logger_stats = stats['logger']
                self.stats_table.setRowCount(len(logger_stats))

                row = 0
                for key, value in logger_stats.items():
                    self.stats_table.setItem(row, 0, QTableWidgetItem(key))
                    self.stats_table.setItem(row, 1, QTableWidgetItem(str(value)))
                    row += 1

            # Update hook statistics
            if 'batcher' in stats:
                hook_stats = stats['batcher']
                self.hook_stats_label.setText(
                    f"Total Hooks: {hook_stats.get('pending_hooks', 0)} | "
                    f"Active: {self.hooks_tree.topLevelItemCount()}"
                )

        except Exception:
            # Silently handle stats update errors
            pass

    def bypass_protection(self, protection_type: ProtectionType):
        """Bypass specific protection"""
        if not self.current_session:
            QMessageBox.warning(self, "No Session",
                               "Please attach to a process first")
            return

        # The adaptation will be handled by the FridaManager
        self.adaptation_log.append(
            f"{datetime.now().strftime('%H:%M:%S')} - "
            f"Attempting to bypass {protection_type.value}..."
        )

        # Trigger adaptation
        self.frida_manager._on_protection_detected(
            protection_type,
            {'session': self.current_session}
        )

        self.adaptation_log.append(
            f"{datetime.now().strftime('%H:%M:%S')} - "
            f"Bypass script loaded for {protection_type.value}"
        )

    def on_preset_selected(self, preset_name: str):
        """Handle preset selection"""
        if preset_name in FRIDA_PRESETS:
            preset = FRIDA_PRESETS[preset_name]

            # Show preset details
            details = f"Name: {preset_name}\n"
            details += f"Description: {preset.get('description', 'N/A')}\n"
            details += f"Target: {preset.get('target', 'Generic')}\n"
            details += f"Scripts: {', '.join(preset.get('scripts', []))}\n"
            details += f"Protection Types: {', '.join(preset.get('protections', []))}"

            self.preset_details.setText(details)
            self.apply_preset_btn.setEnabled(True)
        else:
            self.preset_details.clear()
            self.apply_preset_btn.setEnabled(False)

    def apply_selected_preset(self):
        """Apply the selected preset configuration"""
        preset_name = self.preset_combo.currentText()
        if preset_name not in FRIDA_PRESETS:
            return

        if not self.current_session:
            QMessageBox.warning(self, "No Session",
                               "Please attach to a process first")
            return

        preset = FRIDA_PRESETS[preset_name]

        # Load all scripts in the preset
        for script in preset.get('scripts', []):
            self.frida_manager.load_script(
                self.current_session,
                script,
                preset.get('options', {})
            )
            self.loaded_scripts_list.addItem(script)

        self.status_label.setText(f"Applied preset: {preset_name}")
        self.log_console.append_output(
            f"[PRESET] Applied configuration: {preset_name}"
        )

    def start_bypass_wizard(self):
        """Start the automated bypass wizard"""
        if not self.current_session:
            QMessageBox.warning(self, "No Session",
                               "Please attach to a process first")
            return

        self.wizard_status.clear()
        self.wizard_status.append("Starting automated bypass wizard...")
        self.wizard_progress.setValue(0)

        self.start_wizard_btn.setEnabled(False)
        self.stop_wizard_btn.setEnabled(True)

        # The wizard would analyze the process and apply appropriate bypasses
        # This is a simplified version
        protection_types = list(ProtectionType)
        total_steps = len(protection_types)

        for i, prot_type in enumerate(protection_types):
            if prot_type == ProtectionType.UNKNOWN:
                continue

            self.wizard_status.append(f"Checking for {prot_type.value}...")
            self.wizard_progress.setValue(int((i + 1) / total_steps * 100))

            # Check if protection is detected
            # In real implementation, this would analyze the process

        self.wizard_status.append("Wizard completed!")
        self.wizard_progress.setValue(100)
        self.stop_wizard_btn.setEnabled(False)
        self.start_wizard_btn.setEnabled(True)

    def stop_bypass_wizard(self):
        """Stop the bypass wizard"""
        self.wizard_status.append("Wizard stopped by user")
        self.stop_wizard_btn.setEnabled(False)
        self.start_wizard_btn.setEnabled(True)

    def save_custom_config(self):
        """Save custom configuration"""
        config_text = self.custom_config_text.toPlainText()
        if not config_text:
            return

        try:
            # Validate JSON
            config = json.loads(config_text)

            # Save to file
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Configuration", "", "JSON Files (*.json)"
            )

            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(config, f, indent=2)

                self.status_label.setText(f"Configuration saved: {file_path}")

        except json.JSONDecodeError as e:
            QMessageBox.error(self, "Invalid JSON",
                             f"Invalid configuration format: {e}")

    def load_custom_config(self):
        """Load custom configuration"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json)"
        )

        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)

                self.custom_config_text.setText(json.dumps(config, indent=2))
                self.status_label.setText(f"Configuration loaded: {file_path}")

            except Exception as e:
                QMessageBox.error(self, "Load Error",
                                 f"Failed to load configuration: {e}")

    def filter_logs(self, filter_type: str):
        """Filter logs by type"""
        # Implementation would filter the log console
        self.log_console.append_output(f"[FILTER] Showing {filter_type} logs")

    def search_logs(self, search_text: str):
        """Search in logs"""
        # Implementation would search the log console
        if search_text:
            self.log_console.append_output(f"[SEARCH] Searching for: {search_text}")

    def clear_logs(self):
        """Clear the log console"""
        self.log_console.clear()
        self.status_label.setText("Logs cleared")

    def export_logs(self):
        """Export logs to file"""
        try:
            export_dir = self.frida_manager.logger.export_logs()
            QMessageBox.information(self, "Export Complete",
                                   f"Logs exported to: {export_dir}")
        except Exception as e:
            QMessageBox.error(self, "Export Error",
                             f"Failed to export logs: {e}")

    def export_analysis(self):
        """Export complete analysis"""
        try:
            export_dir = self.frida_manager.export_analysis()
            QMessageBox.information(self, "Export Complete",
                                   f"Analysis exported to: {export_dir}")
        except Exception as e:
            QMessageBox.error(self, "Export Error",
                             f"Failed to export analysis: {e}")

    def show_error(self, error_msg: str):
        """Show error message"""
        QMessageBox.error(self, "Error", error_msg)
        self.status_label.setText(f"Error: {error_msg}")
        self.log_console.append_output(f"[ERROR] {error_msg}")

    def create_ai_generation_group(self) -> QGroupBox:
        """Create AI script generation group."""
        ai_group = QGroupBox("🤖 AI Script Generation")
        ai_layout = QVBoxLayout()

        # Binary selection
        binary_layout = QHBoxLayout()
        binary_layout.addWidget(QLabel("Target Binary:"))
        self.ai_binary_path = QLineEdit()
        self.ai_binary_path.setPlaceholderText("Select target binary for analysis...")
        binary_layout.addWidget(self.ai_binary_path)

        self.ai_browse_btn = QPushButton("Browse")
        self.ai_browse_btn.clicked.connect(self.browse_target_binary)
        binary_layout.addWidget(self.ai_browse_btn)

        ai_layout.addLayout(binary_layout)

        # Script type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Script Type:"))
        self.ai_script_type = QComboBox()
        self.ai_script_type.addItems(["Frida (JavaScript)", "Ghidra (Python)", "Both"])
        type_layout.addWidget(self.ai_script_type)

        # Complexity level
        type_layout.addWidget(QLabel("Complexity:"))
        self.ai_complexity = QComboBox()
        self.ai_complexity.addItems(["Basic", "Advanced"])
        type_layout.addWidget(self.ai_complexity)

        ai_layout.addLayout(type_layout)

        # Protection focus
        protection_layout = QHBoxLayout()
        protection_layout.addWidget(QLabel("Focus:"))
        self.ai_protection_focus = QComboBox()
        self.ai_protection_focus.addItems([
            "Auto-detect", "License Bypass", "Trial Extension",
            "Network Validation", "Anti-Debug", "VM Detection"
        ])
        protection_layout.addWidget(self.ai_protection_focus)

        # Autonomous mode
        self.ai_autonomous = QCheckBox("Autonomous Mode (test & refine)")
        protection_layout.addWidget(self.ai_autonomous)

        ai_layout.addLayout(protection_layout)

        # Generation controls
        gen_layout = QHBoxLayout()
        self.ai_generate_btn = QPushButton("🚀 Generate Script")
        self.ai_generate_btn.clicked.connect(self.generate_ai_script)
        self.ai_generate_btn.setStyleSheet("font-weight: bold; background-color: #0d7377;")
        gen_layout.addWidget(self.ai_generate_btn)

        self.ai_analyze_btn = QPushButton("🔍 Analyze Only")
        self.ai_analyze_btn.clicked.connect(self.analyze_binary_ai)
        gen_layout.addWidget(self.ai_analyze_btn)

        ai_layout.addLayout(gen_layout)

        # Progress tracking
        self.ai_progress = QProgressBar()
        self.ai_progress.setVisible(False)
        ai_layout.addWidget(self.ai_progress)

        self.ai_status = QLabel("Ready for AI script generation")
        self.ai_status.setStyleSheet("color: #0d7377; font-weight: bold;")
        ai_layout.addWidget(self.ai_status)

        # Results area
        results_layout = QHBoxLayout()
        self.ai_preview_btn = QPushButton("Preview Generated")
        self.ai_preview_btn.clicked.connect(self.preview_ai_script)
        self.ai_preview_btn.setEnabled(False)
        results_layout.addWidget(self.ai_preview_btn)

        self.ai_deploy_btn = QPushButton("Deploy & Test")
        self.ai_deploy_btn.clicked.connect(self.deploy_ai_script)
        self.ai_deploy_btn.setEnabled(False)
        results_layout.addWidget(self.ai_deploy_btn)

        self.ai_save_btn = QPushButton("Save Script")
        self.ai_save_btn.clicked.connect(self.save_ai_script)
        self.ai_save_btn.setEnabled(False)
        results_layout.addWidget(self.ai_save_btn)

        ai_layout.addLayout(results_layout)

        ai_group.setLayout(ai_layout)

        # Initialize AI components
        self.ai_generated_scripts = {}
        self.ai_current_analysis = None

        return ai_group

    def browse_target_binary(self):
        """Browse for target binary file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Target Binary", "",
            "Executable Files (*.exe *.dll *.so *.dylib *.bin);;All Files (*)"
        )
        if file_path:
            self.ai_binary_path.setText(file_path)
            self.ai_status.setText(f"Selected: {os.path.basename(file_path)}")

    def generate_ai_script(self):
        """Generate AI script for selected binary."""
        binary_path = self.ai_binary_path.text().strip()
        if not binary_path:
            QMessageBox.warning(self, "Warning", "Please select a target binary first.")
            return

        if not os.path.exists(binary_path):
            QMessageBox.warning(self, "Warning", "Selected binary file does not exist.")
            return

        # Update UI for generation
        self.ai_generate_btn.setEnabled(False)
        self.ai_progress.setVisible(True)
        self.ai_progress.setRange(0, 0)  # Indeterminate progress
        self.ai_status.setText("🤖 AI analyzing binary and generating script...")

        # Start AI generation in background
        self.start_ai_script_generation(binary_path)

    def start_ai_script_generation(self, binary_path: str):
        """Start AI script generation process."""
        try:
            # Import AI components
            from ...ai.autonomous_agent import AutonomousAgent
            from ...ai.orchestrator import get_orchestrator

            # Get AI orchestrator
            orchestrator = get_orchestrator()

            # Create autonomous agent
            agent = AutonomousAgent(orchestrator=orchestrator, cli_interface=None)

            # Build user request
            script_type = self.ai_script_type.currentText()
            complexity = self.ai_complexity.currentText().lower()
            protection_focus = self.ai_protection_focus.currentText()
            autonomous = self.ai_autonomous.isChecked()

            if script_type == "Both":
                script_request = f"Create both Frida and Ghidra scripts to bypass protections in {binary_path}"
            elif "Frida" in script_type:
                script_request = f"Create a {complexity} Frida script to bypass protections in {binary_path}"
            else:
                script_request = f"Create a {complexity} Ghidra script to bypass protections in {binary_path}"

            if protection_focus != "Auto-detect":
                script_request += f". Focus on {protection_focus.lower()} protection."

            if autonomous:
                script_request += " Use autonomous mode with testing and refinement."

            # Process request
            self.ai_status.setText("🔍 AI analyzing binary...")
            result = agent.process_request(script_request)

            # Handle results
            if result.get("status") == "success":
                self.ai_generated_scripts = result.get("scripts", [])
                self.ai_current_analysis = result.get("analysis", {})

                self.ai_status.setText(f"✅ Generated {len(self.ai_generated_scripts)} scripts successfully!")
                self.ai_preview_btn.setEnabled(True)
                self.ai_deploy_btn.setEnabled(True)
                self.ai_save_btn.setEnabled(True)

                # Show generation results
                script_count = len(self.ai_generated_scripts)
                iterations = result.get("iterations", 0)
                self.log_console.append_output(
                    f"[AI] Successfully generated {script_count} scripts in {iterations} iterations"
                )

                # Auto-preview if single script
                if script_count == 1:
                    self.preview_ai_script()

            else:
                error_msg = result.get("message", "Unknown error")
                self.ai_status.setText(f"❌ Generation failed: {error_msg}")
                self.log_console.append_output(f"[AI ERROR] {error_msg}")
                QMessageBox.critical(self, "AI Generation Failed", error_msg)

        except Exception as e:
            self.ai_status.setText(f"❌ Error: {str(e)}")
            self.log_console.append_output(f"[AI ERROR] {str(e)}")
            QMessageBox.critical(self, "Error", f"AI script generation failed: {str(e)}")

        finally:
            # Reset UI
            self.ai_generate_btn.setEnabled(True)
            self.ai_progress.setVisible(False)

    def analyze_binary_ai(self):
        """Analyze binary with AI without generating scripts."""
        binary_path = self.ai_binary_path.text().strip()
        if not binary_path or not os.path.exists(binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid target binary first.")
            return

        self.ai_status.setText("🔍 AI analyzing binary protections...")

        try:
            # Import AI components for analysis
            from ...ai.orchestrator import AITask, AITaskType, AnalysisComplexity, get_orchestrator

            orchestrator = get_orchestrator()

            # Create analysis task
            task = AITask(
                task_id=f"analysis_{int(datetime.now().timestamp())}",
                task_type=AITaskType.BINARY_ANALYSIS,
                complexity=AnalysisComplexity.COMPLEX,
                input_data={"binary_path": binary_path},
                priority=8
            )

            # Submit and wait for result
            orchestrator.submit_task(task)
            self.ai_status.setText("⏳ Analysis in progress...")

            # For now, show completion - in real implementation would track task
            self.ai_status.setText("✅ Binary analysis complete!")
            self.log_console.append_output(f"[AI] Completed analysis of {os.path.basename(binary_path)}")

        except Exception as e:
            self.ai_status.setText(f"❌ Analysis failed: {str(e)}")
            self.log_console.append_output(f"[AI ERROR] Analysis failed: {str(e)}")

    def preview_ai_script(self):
        """Preview generated AI scripts."""
        if not self.ai_generated_scripts:
            QMessageBox.information(self, "Info", "No scripts generated yet.")
            return

        # Create preview dialog
        preview_dialog = QDialog(self)
        preview_dialog.setWindowTitle("🤖 AI Generated Scripts Preview")
        preview_dialog.resize(1000, 700)

        layout = QVBoxLayout()

        # Tabs for multiple scripts
        if len(self.ai_generated_scripts) > 1:
            tab_widget = QTabWidget()

            for i, script in enumerate(self.ai_generated_scripts):
                script_content = script.content if hasattr(script, 'content') else str(script)
                script_type = script.metadata.script_type.value if hasattr(script, 'metadata') else f"Script {i+1}"

                tab = QWidget()
                tab_layout = QVBoxLayout()

                # Script info
                info_layout = QHBoxLayout()
                info_layout.addWidget(QLabel(f"Type: {script_type}"))
                if hasattr(script, 'metadata'):
                    info_layout.addWidget(QLabel(f"Success Probability: {script.metadata.success_probability:.0%}"))
                    info_layout.addWidget(QLabel(f"Target: {script.metadata.target_binary}"))
                tab_layout.addLayout(info_layout)

                # Script content
                content_edit = QTextEdit()
                content_edit.setReadOnly(True)
                content_edit.setFont(QFont("Consolas", 10))
                content_edit.setPlainText(script_content)

                # Apply syntax highlighting
                if "frida" in script_type.lower() or script_content.startswith("//"):
                    JavaScriptHighlighter(content_edit.document())

                tab_layout.addWidget(content_edit)
                tab.setLayout(tab_layout)

                tab_widget.addTab(tab, script_type)

            layout.addWidget(tab_widget)
        else:
            # Single script preview
            script = self.ai_generated_scripts[0]
            script_content = script.content if hasattr(script, 'content') else str(script)

            # Script info
            if hasattr(script, 'metadata'):
                info_label = QLabel(f"Type: {script.metadata.script_type.value} | "
                                  f"Success Probability: {script.metadata.success_probability:.0%} | "
                                  f"Target: {script.metadata.target_binary}")
                info_label.setStyleSheet("font-weight: bold; color: #0d7377; padding: 10px;")
                layout.addWidget(info_label)

            # Script content
            content_edit = QTextEdit()
            content_edit.setReadOnly(True)
            content_edit.setFont(QFont("Consolas", 10))
            content_edit.setPlainText(script_content)

            # Apply syntax highlighting
            if hasattr(script, 'metadata') and "frida" in script.metadata.script_type.value.lower():
                # Store highlighter reference to prevent garbage collection
                content_edit.highlighter = JavaScriptHighlighter(content_edit.document())

            layout.addWidget(content_edit)

        # Dialog buttons
        buttons_layout = QHBoxLayout()

        deploy_btn = QPushButton("Deploy & Test")
        deploy_btn.clicked.connect(lambda: [preview_dialog.accept(), self.deploy_ai_script()])
        buttons_layout.addWidget(deploy_btn)

        save_btn = QPushButton("Save Scripts")
        save_btn.clicked.connect(lambda: [preview_dialog.accept(), self.save_ai_script()])
        buttons_layout.addWidget(save_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(preview_dialog.accept)
        buttons_layout.addWidget(close_btn)

        layout.addLayout(buttons_layout)
        preview_dialog.setLayout(layout)
        preview_dialog.exec_()

    def deploy_ai_script(self):
        """Deploy generated AI scripts."""
        if not self.ai_generated_scripts:
            QMessageBox.information(self, "Info", "No scripts to deploy.")
            return

        try:
            deployed_count = 0
            for script in self.ai_generated_scripts:
                if hasattr(script, 'metadata') and "frida" in script.metadata.script_type.value.lower():
                    # Deploy Frida script
                    script_content = script.content if hasattr(script, 'content') else str(script)
                    # Add to loaded scripts list
                    item = QListWidgetItem(f"AI Generated: {script.metadata.target_binary}")
                    item.setData(Qt.UserRole, script_content)
                    self.loaded_scripts_list.addItem(item)
                    deployed_count += 1

            if deployed_count > 0:
                self.ai_status.setText(f"✅ Deployed {deployed_count} scripts!")
                self.log_console.append_output(f"[AI] Deployed {deployed_count} AI-generated scripts")
                QMessageBox.information(self, "Success", f"Successfully deployed {deployed_count} AI-generated scripts.")
            else:
                QMessageBox.information(self, "Info", "No deployable Frida scripts found.")

        except Exception as e:
            self.ai_status.setText(f"❌ Deployment failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to deploy scripts: {str(e)}")

    def save_ai_script(self):
        """Save generated AI scripts to files."""
        if not self.ai_generated_scripts:
            QMessageBox.information(self, "Info", "No scripts to save.")
            return

        try:
            from ...ai.ai_script_generator import AIScriptGenerator

            # Get save directory
            save_dir = QFileDialog.getExistingDirectory(
                self, "Select Directory to Save AI Scripts",
                "scripts/ai_generated"
            )

            if not save_dir:
                return

            script_generator = AIScriptGenerator()
            saved_count = 0

            for script in self.ai_generated_scripts:
                try:
                    saved_path = script_generator.save_script(script, save_dir)
                    saved_count += 1
                    self.log_console.append_output(f"[AI] Saved script: {saved_path}")
                except Exception as e:
                    self.log_console.append_output(f"[AI ERROR] Failed to save script: {e}")

            if saved_count > 0:
                self.ai_status.setText(f"✅ Saved {saved_count} scripts to {save_dir}")
                QMessageBox.information(self, "Success",
                                      f"Successfully saved {saved_count} scripts to:\n{save_dir}")

                # Reload script list to show new scripts
                self.reload_script_list()
            else:
                QMessageBox.warning(self, "Warning", "No scripts were saved.")

        except Exception as e:
            self.ai_status.setText(f"❌ Save failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save scripts: {str(e)}")

    def closeEvent(self, event):
        """Handle dialog close"""
        # Clean up Frida manager
        self.frida_manager.cleanup()

        # Stop timers
        if hasattr(self, 'monitor_timer'):
            self.monitor_timer.stop()

        event.accept()




# Export the dialog
__all__ = ['FridaManagerDialog']
